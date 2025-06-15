/// <reference types="jest" />

declare namespace NodeJS {
  interface Global {
    fetch: jest.MockedFunction<typeof fetch>;
    AbortController: typeof AbortController;
  }
}