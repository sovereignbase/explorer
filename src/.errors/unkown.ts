import { ExplorerError } from './class.js'

/**
 * Preserves an existing library error or wraps an unexpected failure once.
 * @param cause The value thrown by the failed operation.
 * @param operation The operation name to include in the error message.
 * @returns The original library error, or an `UNKNOWN_ERROR` retaining `cause`.
 */
export function unknownError(cause: unknown, operation: string): ExplorerError {
  return cause instanceof ExplorerError
    ? cause
    : new ExplorerError('UNKNOWN_ERROR', `${operation} failed.`, { cause })
}
