import type { RecentEntriesDelta } from '../RecentEntries/class.js'
import type { CredentialEntriesDelta } from '../CredentialEntries/class.js'

export type AuthenticationResult =
  'authenticated' | 'authenticator-error' | 'invalid-data-pin'

export type AuthenticationSetupParams = Readonly<{
  credentialName: string
  setupParamas: string
}>

export type ExplorerDelta =
  RecentEntriesDelta | CredentialEntriesDelta | ['other' | []]

/**
 * Maps text event names to their `CustomEvent.detail` payloads.
 */
export type ExplorerEventMap = {
  authenticated: boolean
  delta: ExplorerDelta
}

/**
 * A callback or listener object for a text event.
 *
 * @typeParam K The event name that determines the event's `detail` type.
 */
export type ExplorerEventListener<K extends keyof ExplorerEventMap> =
  | ((event: CustomEvent<ExplorerEventMap[K]>) => void)
  | { handleEvent(event: CustomEvent<ExplorerEventMap[K]>): void }

/**
 * Resolves a document event name to its typed listener, or uses a DOM event
 * listener for an unrecognized event name.
 *
 * @typeParam K The event name to resolve.
 */
export type ExplorerEventListenerFor<K extends string> =
  K extends keyof ExplorerEventMap
    ? ExplorerEventListener<K>
    : EventListenerOrEventListenerObject
