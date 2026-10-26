/** Identifies a library error independently of its human-readable message. */
export type ExplorerErrorCode =
  /** An unexpected failure was wrapped with its original cause. */
  'UNKNOWN_ERROR'

/** An error with a library-prefixed message, a stable code and an optional cause. */
export class ExplorerError extends Error {
  /** The machine-readable category of the failure. */
  readonly code: ExplorerErrorCode

  /**
   * Creates an error whose name is `ExplorerError`.
   * @param code The category of the failure.
   * @param message The detail to prefix with the library name; defaults to `code`.
   * @param options Error options, including the original `cause`.
   */
  constructor(
    code: ExplorerErrorCode,
    message?: string,
    options?: ErrorOptions
  ) {
    const detail = message ?? code
    super(`{@sovereignbase/explorer} ${detail}`, options)
    this.code = code
    this.name = 'ExplorerError'
  }
}
