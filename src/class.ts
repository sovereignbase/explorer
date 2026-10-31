import {
  deleteObject,
  loadObject,
  storeObject,
  type URLString,
} from '@sovereignbase/storage'
import { isRecord, type DeepReadonly } from '@sovereignbase/utils'
import { Bytes } from '@sovereignbase/bytecodec'
import { readableUserAgent } from '@sovereignbase/dom-utils'
import {
  accessDeviceBinding,
  createDeviceBinding,
} from '@sovereignbase/hardware-bound'
import {
  Cryptographic,
  type DecapsulateKey,
  type EncapsulateKey,
  type KeyOffer,
  type CipherKey,
  type CipherMessage,
} from '@sovereignbase/cryptosuite'
//
import type {
  AuthenticationResult,
  AuthenticationSetupParams,
  //
  ExplorerEventMap,
  ExplorerEventListenerFor,
  //
  ExplorerDelta,
} from './.types/type.js'
//
import { ExplorerError } from './.errors/class.js'
import { unknownError } from './.errors/unkown.js'
//
import {
  CredentialEntries,
  type CredentialEntry,
  type CredentialEvent,
  type CredentialEntriesChange,
} from './CredentialEntries/class.js'
//
import {
  RecentEntries,
  type RecentEntry,
  type RecentEntriesChange,
} from './RecentEntries/class.js'

/**
 * Provides access to an authenticated Sovereignbase database.
 *
 * Manages database authentication, encrypted object storage, credential
 * registration, database linking, and synchronized entries.
 */
export class Explorer {
  /** The identifier of the authenticated database. */
  public static databaseID: string

  /** Indicates whether a database has been authenticated. */
  public static isAuthenticated: boolean

  /** The base URL used to access database objects. */
  private static storageURL: URLString

  /** The event target used for Explorer events. */
  private static eventTarget?: EventTarget

  /** The data PIN associated with the current session. */
  private static dataPIN: string

  /** The virtual entropy associated with the authenticated database. */
  private static virtualEntropy: Readonly<Uint8Array>

  /** The secret used to access the authenticated database. */
  private static databaseSecret: Readonly<Uint8Array>

  /** The credential information associated with the current authentication. */
  private static sessionCredential?: CredentialEvent = {}

  /**
   * Caches cipher keys by object identifier.
   *
   * Existing entries are preserved when an object is accessed with
   * a cipher key.
   */
  public static readonly cipherKeyCache: Map<string, CipherKey> = new Map()

  /**
   * Authenticates a database using a data PIN and an existing device binding.
   *
   * Establishes the authenticated database context and records the credential
   * used for authentication.
   *
   * When setup parameters are provided, registers a credential using the
   * supplied virtual entropy or generates new virtual entropy.
   *
   * @param dataPIN The PIN associated with the database.
   * @param storageURL The base URL used to access database objects.
   * @param setupParams Optional parameters for registering a credential.
   *
   * @param credentialId An optional credential identifier used to restrict credential selection.
   * @returns The authentication result.
   */
  public static async authenticate(
    dataPIN: string,
    storageURL: URLString,
    setupParams?: AuthenticationSetupParams,
    credentialId?: string
  ): Promise<AuthenticationResult> {
    try {
      this.dataPIN = dataPIN
      this.storageURL = storageURL
      //
      const deviceBinding = await accessDeviceBinding(credentialId)
      if (!Array.isArray(deviceBinding)) return 'authenticator-error'
      const [credentialID, deviceEntropy] = deviceBinding
      //
      this.sessionCredential = {
        timestamp: Date.now(),
        userAgent: readableUserAgent(),
      }
      //
      const dataPINBytes = Bytes.utf8.decode(dataPIN)
      //
      const credentialSecret = await Bytes.derive(
        deviceEntropy,
        dataPINBytes,
        32
      )
      //
      const credentialObjectID = await Cryptographic.identifier.derive(
        credentialSecret,
        Bytes.utf8.decode('@sovereignbase/explorer:CredentialObjectID'),
        32
      )
      this.sessionCredential.objectID = credentialObjectID
      this.sessionCredential.credentialID = credentialID
      //
      const credentialObjectCK = await Cryptographic.cipherMessage.deriveKey(
        credentialSecret,
        Bytes.utf8.decode('@sovereignbase/explorer:CredentialObjectCK')
      )
      //
      ////////
      // SETUP
      if (isRecord(setupParams)) {
        this.virtualEntropy =
          setupParams.virtualEntropy instanceof Uint8Array
            ? setupParams.virtualEntropy
            : Bytes.generate(64)

        void (await this.storeObjectByID(
          credentialObjectID,
          this.virtualEntropy,
          credentialObjectCK
        ))

        this.sessionCredential.name = setupParams.credentialName
        this.sessionCredential.entropy = deviceEntropy
        this.sessionCredential.storage = setupParams.bindingStorage
      }
      ////////
      // LOGIN
      else {
        const result = await this.loadObjectByID(
          credentialObjectID,
          credentialObjectCK
        )
        if (!(result instanceof Uint8Array) || result.byteLength !== 64)
          return 'invalid-data-pin'

        this.virtualEntropy = result
      }
      //
      this.databaseSecret = await Bytes.derive(
        this.virtualEntropy,
        dataPINBytes,
        64
      )

      this.databaseID = await Cryptographic.identifier.derive(
        this.databaseSecret,
        Bytes.utf8.decode('@sovereignbase/explorer:DatabaseID'),
        32
      )

      const databaseCipherKey = await Cryptographic.cipherMessage.deriveKey(
        this.databaseSecret,
        Bytes.utf8.decode('@sovereignbase/explorer:DatabaseCK')
      )

      void this.cipherKeyCache.set(this.databaseID, databaseCipherKey)

      this.isAuthenticated = true

      void (await this.loadCredentialEntries()).record(this.sessionCredential)
      delete this.sessionCredential

      void this.dispatchEvent('authenticated', true)

      return 'authenticated'
    } catch (cause) {
      throw unknownError(cause, 'Explorer.authenticate()')
    }
  }

  /** The number of consecutive failed database linking PIN attempts. */
  private static failCounter: number = 0

  /**
   * Prepares an authenticated database for linking to another device.
   *
   * Verifies the current data PIN and prepares an encrypted transfer
   * containing the information required to access the same database.
   *
   * Repeated PIN failures cause the current page to reload.
   *
   * @param dataPIN The PIN associated with the authenticated database.
   * @param encapsulateKey The key used to establish encryption for the transfer.
   * @returns The key offer and encrypted transfer message, or `false`
   * if the supplied PIN is incorrect.
   */
  public static async prepareDatabaseLink(
    dataPIN: string,
    encapsulateKey: EncapsulateKey
  ): Promise<[keyOffer: KeyOffer, cipherMessage: CipherMessage] | false> {
    try {
      if (!this.isAuthenticated) throw new ExplorerError('NOT_AUTHENTICATED')

      if (dataPIN !== this.dataPIN) {
        if (this.failCounter >= 2) void window.location.reload() // log out
        this.failCounter++
        return false
      }

      this.failCounter = 0

      const { keyOffer, cipherKey } =
        await Cryptographic.keyAgreement.encapsulate(encapsulateKey)

      const cipherMessage = await Cryptographic.cipherMessage.encrypt(
        cipherKey,
        Bytes.concat([this.virtualEntropy, Bytes.utf8.decode(dataPIN)])
      )

      return [keyOffer, cipherMessage]
    } catch (cause) {
      throw unknownError(cause, 'Explorer.prepareDatabaseLink()')
    }
  }

  /**
   * Links the current device to an existing database.
   *
   * Accesses the transferred database information, creates a device binding,
   * and registers a credential for the existing database.
   *
   * @param keyOffer The key offer associated with the database link.
   * @param cipherMessage The encrypted database linking message.
   * @param decapsulateKey The key used to establish decryption for the transfer.
   * @param credentialName The display name assigned to the new credential.
   * @param storageURL The base URL used to access database objects.
   * @returns `true` if the database was linked and authenticated;
   * otherwise, `false`.
   */
  public static async linkToDatabase(
    keyOffer: KeyOffer,
    cipherMessage: CipherMessage,
    decapsulateKey: DecapsulateKey,
    credentialName: string,
    storageURL: URLString
  ): Promise<boolean> {
    try {
      const { cipherKey } = await Cryptographic.keyAgreement.decapsulate(
        keyOffer,
        decapsulateKey
      )
      const raw = await Cryptographic.cipherMessage.decrypt(
        cipherKey,
        cipherMessage
      )

      const setupResult = await createDeviceBinding(credentialName)
      if (!Array.isArray(setupResult)) return false
      const [credentialId, bindingStorage] = setupResult

      const result = await this.authenticate(
        Bytes.utf8.encode(raw.slice(64)),
        storageURL,
        {
          credentialName,
          virtualEntropy: raw.slice(0, 64),
          bindingStorage,
        },
        credentialId
      )

      return result === 'authenticated' ? true : false
    } catch (cause) {
      throw unknownError(cause, 'Explorer.linkToDatabase()')
    }
  }

  /**
   * Permanently revokes a registered database credential.
   *
   * Removes the credential's persisted data and registration from
   * the authenticated database.
   *
   * @param credentialID The identifier of the credential to revoke.
   * @throws {ExplorerError} If the database is not authenticated.
   */
  public static async permanentlyDeleteCredential(
    credentialID: string
  ): Promise<void> {
    try {
      return void (await (
        await this.loadCredentialEntries()
      ).revoke(credentialID))
    } catch (cause) {
      throw unknownError(cause, 'Explorer.permanentlyDeleteCredential()')
    }
  }

  /**
   * Returns the registered database credentials.
   *
   * Optionally registers a listener for changes to the credential entries.
   * The returned cleanup function removes the registered listener.
   *
   * @param onChange An optional callback invoked when the entries change.
   * @returns The cleanup function, credential entries, and identifier
   * of the current session's credential.
   * @throws {ExplorerError} If the database is not authenticated.
   */
  public static async listCredentialEntries(
    onChange?: (splice: CredentialEntriesChange) => void
  ): Promise<
    [
      cleanup: () => void,
      entries: DeepReadonly<Array<CredentialEntry>>,
      sessionCredentialID: string,
    ]
  > {
    try {
      const credentialEntries = await this.loadCredentialEntries()

      const listener = onChange
        ? ({ detail }: CustomEvent<CredentialEntriesChange>) => onChange(detail)
        : undefined

      if (listener) credentialEntries.addEventListener('change', listener)

      return [
        () => {
          if (listener)
            credentialEntries.removeEventListener('change', listener)
        },
        credentialEntries.list(),
        credentialEntries.sessionCredentialID,
      ]
    } catch (cause) {
      throw unknownError(cause, 'Explorer.listCredentialEntries()')
    }
  }

  /**
   * Returns the recently accessed database objects.
   *
   * Optionally registers a listener for changes to the recent entries.
   * The returned cleanup function removes the registered listener.
   *
   * @param onChange An optional callback invoked when the entries change.
   * @returns The cleanup function and recent entries.
   * @throws {ExplorerError} If the database is not authenticated.
   */
  public static async listRecentEntries(
    onChange?: (splice: RecentEntriesChange) => void
  ): Promise<[cleanup: () => void, entries: DeepReadonly<Array<RecentEntry>>]> {
    try {
      const recentEntries = await this.loadRecentEntries()

      const listener = onChange
        ? ({ detail }: CustomEvent<RecentEntriesChange>) => onChange(detail)
        : undefined

      if (listener) recentEntries.addEventListener('change', listener)

      return [
        () => {
          if (listener) recentEntries.removeEventListener('change', listener)
        },
        recentEntries.list(),
      ]
    } catch (cause) {
      throw unknownError(cause, 'Explorer.listRecentEntries()')
    }
  }

  /**
   * Loads an encrypted database object by its identifier.
   *
   * Caches the supplied cipher key if no key has been cached for the object.
   *
   * @typeParam T The expected type of the loaded object.
   * @param id The identifier of the object to load.
   * @param cipherKey The key used to decrypt the object.
   * @param onNetworkResponse An optional callback for network responses.
   * @returns The loaded object, or `undefined` if no object is available.
   */
  public static async loadObjectByID<T>(
    id: string,
    cipherKey: CipherKey,
    onNetworkResponse?: (data: unknown) => void | Promise<void>
  ): Promise<T | undefined> {
    try {
      if (!this.cipherKeyCache.has(id))
        void this.cipherKeyCache.set(id, cipherKey)
      //
      return (await loadObject(
        (this.storageURL + id) as URLString,
        cipherKey,
        false,
        onNetworkResponse
      )) as T
    } catch (cause) {
      throw unknownError(cause, 'Explorer.loadObjectByID()')
    }
  }

  /**
   * Encrypts and stores a database object by its identifier.
   *
   * Caches the supplied cipher key if no key has been cached for the object.
   *
   * @typeParam T The type of the object to store.
   * @param id The identifier of the object to store.
   * @param object The object to encrypt and store.
   * @param cipherKey The key used to encrypt the object.
   */
  public static async storeObjectByID<T>(
    id: string,
    object: T,
    cipherKey: CipherKey
  ): Promise<void> {
    try {
      if (!this.cipherKeyCache.has(id))
        void this.cipherKeyCache.set(id, cipherKey)
      //
      return void (await storeObject(
        (this.storageURL + id) as URLString,
        object,
        cipherKey
      ))
    } catch (cause) {
      throw unknownError(cause, 'Explorer.storeObjectByID()')
    }
  }

  /**
   * Deletes a database object by its identifier.
   *
   * Removes the persisted object and its corresponding recent entry.
   *
   * @param id The identifier of the object to delete.
   */
  public static async deleteObjectByID(id: string): Promise<void> {
    try {
      void (await deleteObject((this.storageURL + id) as URLString))
      return void (await this.loadRecentEntries()).delete(id)
    } catch (cause) {
      throw unknownError(cause, 'Explorer.deleteObjectByID()')
    }
  }

  /**
   * Schedules the application of a synchronized Explorer delta.
   *
   * Recognized deltas are forwarded to their corresponding entries list.
   * Invalid or unrecognized delta types are ignored.
   *
   * Processing is scheduled in a microtask and is not awaited by the caller.
   *
   * @param data The delta to apply.
   */
  public static apply(data: unknown): void {
    return void queueMicrotask(async () => {
      try {
        if (!this.isExplorerDelta(data)) return
        switch (data[0]) {
          case 'recentEntries': {
            void (await this.loadRecentEntries()).apply(data[1])
            break
          }
          case 'credentialEntries': {
            void (await this.loadCredentialEntries()).apply(data[1])
            break
          }
        }
        return
      } catch (cause) {
        throw unknownError(cause, 'Explorer.apply()')
      }
    })
  }

  //* ███████╗██╗   ██╗███████╗███╗   ██╗████████╗   ████████╗ █████╗ ██████╗  ██████╗ ███████╗████████╗
  //* ██╔════╝██║   ██║██╔════╝████╗  ██║╚══██╔══╝   ╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝╚══██╔══╝
  //* █████╗  ██║   ██║█████╗  ██╔██╗ ██║   ██║         ██║   ███████║██████╔╝██║  ███╗█████╗     ██║
  //* ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║   ██║         ██║   ██╔══██║██╔══██╗██║   ██║██╔══╝     ██║
  //* ███████╗ ╚████╔╝ ███████╗██║ ╚████║   ██║         ██║   ██║  ██║██║  ██║╚██████╔╝███████╗   ██║
  //* ╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ╚═╝         ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝

  /**
   * Registers an event listener for the specified Explorer event.
   *
   * @typeParam K The event name that determines the event detail type.
   * @param type The event type.
   * @param listener The event listener, or `null`.
   * @param options The event listener options.
   */
  public static addEventListener<K extends keyof ExplorerEventMap>(
    type: K,
    listener: ExplorerEventListenerFor<K> | null,
    options?: boolean | AddEventListenerOptions
  ): void {
    try {
      void (this.eventTarget ??= new EventTarget()).addEventListener(
        type,
        listener as EventListenerOrEventListenerObject | null,
        options
      )
    } catch (cause) {
      throw unknownError(cause, 'Explorer.addEventListener()')
    }
  }

  /**
   * Removes an event listener previously registered with
   * {@link addEventListener}.
   *
   * @typeParam K The event name that determines the listener type.
   * @param type The event type.
   * @param listener The event listener to remove, or `null`.
   * @param options The event listener options.
   */
  public static removeEventListener<K extends keyof ExplorerEventMap>(
    type: K,
    listener: ExplorerEventListenerFor<K> | null,
    options?: boolean | EventListenerOptions
  ): void {
    try {
      void this.eventTarget?.removeEventListener(
        type,
        listener as EventListenerOrEventListenerObject | null,
        options
      )
    } catch (cause) {
      throw unknownError(cause, 'Explorer.removeEventListener()')
    }
  }

  /**
   * Dispatches an Explorer event to registered listeners.
   *
   * @typeParam K The event name that determines the event detail type.
   * @param type The event type.
   * @param detail The value exposed through `CustomEvent.detail`.
   */
  public static dispatchEvent<K extends keyof ExplorerEventMap>(
    type: K,
    detail: ExplorerEventMap[K]
  ): void {
    try {
      void this.eventTarget?.dispatchEvent(new CustomEvent(type, { detail }))
    } catch (cause) {
      throw unknownError(cause, 'Explorer.dispatchEvent()')
    }
  }

  //* ██╗  ██╗███████╗██╗     ██████╗ ███████╗██████╗ ███████╗
  //* ██║  ██║██╔════╝██║     ██╔══██╗██╔════╝██╔══██╗██╔════╝
  //* ███████║█████╗  ██║     ██████╔╝█████╗  ██████╔╝███████╗
  //* ██╔══██║██╔══╝  ██║     ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║
  //* ██║  ██║███████╗███████╗██║     ███████╗██║  ██║███████║
  //* ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝

  /**
   * Determines whether a value has the basic structure of an Explorer delta.
   *
   * @param data The value to inspect.
   * @returns Whether the value has a string discriminator.
   */
  private static isExplorerDelta(data: unknown): data is ExplorerDelta {
    return Array.isArray(data) && typeof data[0] === 'string'
  }

  /** The cached recent entries list. */
  private static recentEntries?: RecentEntries

  /**
   * Loads or returns the cached recent entries list.
   *
   * Derives the list identifier and cipher key from the database secret
   * and merges subsequent network responses into the loaded state.
   *
   * @returns The recent entries list.
   * @throws {ExplorerError} If the database is not authenticated.
   */
  private static async loadRecentEntries(): Promise<RecentEntries> {
    try {
      if (!this.isAuthenticated) throw new ExplorerError('NOT_AUTHENTICATED')

      if (this.recentEntries) return this.recentEntries

      const id = await Cryptographic.identifier.derive(
        this.databaseSecret,
        Bytes.utf8.decode('@sovereignbase/explorer:RecentEntriesID'),
        32
      )
      const ck = await Cryptographic.cipherMessage.deriveKey(
        this.databaseSecret,
        Bytes.utf8.decode('@sovereignbase/explorer:RecentEntriesCipherKey')
      )

      const trustedSnapshot = await this.loadObjectByID(
        id,
        ck,
        (snapshot) => void this.recentEntries!.merge(snapshot)
      )

      this.recentEntries = new RecentEntries(id, 0, trustedSnapshot)

      return this.recentEntries
    } catch (cause) {
      throw unknownError(cause, 'Explorer.loadRecentEntries()')
    }
  }

  /** The cached credential entries list. */
  private static credentialEntries?: CredentialEntries

  /**
   * Loads or returns the cached credential entries list.
   *
   * Derives the list identifier and cipher key from the database secret
   * and merges subsequent network responses into the loaded state.
   *
   * @returns The credential entries list.
   * @throws {ExplorerError} If the database is not authenticated.
   */
  private static async loadCredentialEntries(): Promise<CredentialEntries> {
    try {
      if (!this.isAuthenticated) throw new ExplorerError('NOT_AUTHENTICATED')

      if (this.credentialEntries) return this.credentialEntries

      const id = await Cryptographic.identifier.derive(
        this.databaseSecret,
        Bytes.utf8.decode('@sovereignbase/explorer:CredentialEntriesID'),
        32
      )
      const ck = await Cryptographic.cipherMessage.deriveKey(
        this.databaseSecret,
        Bytes.utf8.decode('@sovereignbase/explorer:CredentialEntriesCipherKey')
      )

      const trustedSnapshot = await this.loadObjectByID(
        id,
        ck,
        (snapshot) => void this.credentialEntries!.merge(snapshot)
      )

      this.credentialEntries = new CredentialEntries(
        id,
        this.sessionCredential!.credentialID!,
        0,
        trustedSnapshot
      )

      return this.credentialEntries
    } catch (cause) {
      throw unknownError(cause, 'Explorer.loadCredentialEntries()')
    }
  }
}

export { ExplorerError, type ExplorerErrorCode } from './.errors/class.js'

export * from './.types/type.js'
