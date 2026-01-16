/// <reference lib="dom" />
import * as types from "../src/types";
import { expect } from "chai";

describe("createOptionalCallbackFunction", function () {
  it("should not execute callback twice when callback throws unhandled exception", function (done) {
    const syncFn = (a: number, b: number) => a + b;
    const flexibleFn = types.createOptionalCallbackFunction(syncFn);

    let callbackExecutionCount = 0;

    // Store and remove existing unhandled exception listeners
    const existingListeners = process.rawListeners("uncaughtException");
    process.removeAllListeners("uncaughtException");

    process.once("uncaughtException", (err) => {
      // Restore unhandled exception listeners
      existingListeners.forEach((listener) => {
        process.on("uncaughtException", listener as NodeJS.UncaughtExceptionListener);
      });

      expect(err.message).to.equal("Callback threw an error");
      expect(callbackExecutionCount).to.equal(1);
      done();
    });

    flexibleFn(2, 3, (err, result) => {
      callbackExecutionCount++;
      expect(err).to.be.null;
      expect(result).to.equal(5);

      throw new Error("Callback threw an error");
    });
  });

  it("should defer callback execution in success case", function (done) {
    const syncFn = (a: number, b: number) => a + b;
    const flexibleFn = types.createOptionalCallbackFunction(syncFn);

    let callbackExecuted = false;

    flexibleFn(2, 3, (err, result) => {
      callbackExecuted = true;
      expect(err).to.be.null;
      expect(result).to.equal(5);
      done();
    });

    // Callback should be asynchronously deferred
    expect(callbackExecuted).to.be.false;
  });
});
