/** Expected business-rule failure with a user-safe message. */
export class DomainError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 404 | 409 | 422 = 422,
  ) {
    super(message);
    this.name = "DomainError";
  }
}
