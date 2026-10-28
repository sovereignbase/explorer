/** Identifies an Explorer failure independently of its human-readable message. */
export type ExplorerErrorCode =
  /** An unexpected failure was wrapped with its original cause. */
  | 'UNKNOWN_ERROR'
  /** A credential event is missing required identifying or usage information. */
  | 'INVALID_CREDENTIAL_EVENT'
  /** A new credential does not provide all required setup properties. */
  | 'MISSING_CREDENTIAL_SETUP_PROPERTIES'
  /** An operation requires an authenticated Explorer session. */
  | 'NOT_AUTHENTICATED'

/**
 * An Explorer error with a stable, machine-readable code and an optional cause.
 *
 * The message is prefixed with the library name. Use {@link code} rather than
 * parsing the message when handling a particular failure.
 */
export class ExplorerError extends Error {
  /** The machine-readable category of the failure. */
  readonly code: ExplorerErrorCode

  /**
   * Creates an error whose name is `ExplorerError`.
   *
   * @param code The category of the failure.
   * @param message The detail to prefix with the library name; defaults to `code`.
   * @param options Error options, including the original `cause`.
   */
  constructor(
    code: ExplorerErrorCode,
    message?: string,
    options?: ErrorOptions
  ) {
    super(`{@sovereignbase/explorer} ${message ?? code}`, options)
    this.code = code
    this.name = 'ExplorerError'
  }
}
