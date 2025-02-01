pub const CryptoError = error{
    MessageLengthLimitExceeded,
    BufferSizeMismatch,
    InvalidIVLength,
    InvalidTagLength,
    IncorrectAuthenticationTag,
};
