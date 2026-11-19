/**
 * Progress Notification Utilities
 *
 * Provides progress notification functionality for long-running MCP tool operations.
 * Sends notifications/progress messages to clients that support them.
 */

import { randomUUID } from 'node:crypto';
import type { ServerNotification } from '@modelcontextprotocol/server';
import { logger } from './logger.js';

type ProgressToken = string | number;
type NotificationSender = (notification: ServerNotification) => Promise<void>;

/**
 * Active progress contexts, keyed by an internal per-call token.
 *
 * Tool code only sees the internal token (passed as meta.progressToken), so
 * two sessions that happen to use the same client token can't collide, and
 * each notification goes back through the session that made the call.
 */
const progressContexts = new Map<string, { clientToken: ProgressToken; send: NotificationSender }>();

/**
 * Register a progress context for one tool call.
 * Returns the internal token to pass down as meta.progressToken, and a
 * release() to call when the tool call finishes.
 */
export function registerProgressContext(
  clientToken: ProgressToken | undefined,
  send: NotificationSender
): { token: string | undefined; release: () => void } {
  if (clientToken === undefined) {
    return { token: undefined, release: () => {} };
  }
  const token = randomUUID();
  progressContexts.set(token, { clientToken, send });
  return { token, release: () => { progressContexts.delete(token); } };
}

/**
 * Send a progress notification to the client
 *
 * @param progressToken - Internal token from meta.progressToken (undefined = client didn't ask)
 * @param progress - Current progress value (e.g., 1, 2, 3)
 * @param total - Total number of steps (e.g., 5)
 */
export function sendProgress(
  progressToken: string | undefined,
  progress: number,
  total: number
): void {
  const context = progressToken ? progressContexts.get(progressToken) : undefined;
  if (!context) {
    // Client didn't request progress, or the call already finished
    return;
  }

  // Never let a failed notification (e.g. session closed) crash the process
  context.send({
    method: 'notifications/progress',
    params: { progressToken: context.clientToken, progress, total }
  }).catch((error) => {
    logger.warn('Failed to send progress notification', {
      error: error instanceof Error ? error.message : error,
      progress,
      total
    });
  });
}

/**
 * Create a progress tracker for multi-step operations
 *
 * @param progressToken - Optional progress token from the client request
 * @param totalSteps - Total number of steps in the operation
 * @returns Object with methods to track progress
 *
 * @example
 * ```typescript
 * const tracker = createProgressTracker(meta?.progressToken, 5);
 * tracker.start(); // 0/5
 * await doStep1();
 * tracker.increment(); // 1/5
 * await doStep2();
 * tracker.increment(); // 2/5
 * tracker.complete(); // 5/5
 * ```
 */
export function createProgressTracker(
  progressToken: string | undefined,
  totalSteps: number
) {
  let currentStep = 0;

  return {
    /**
     * Start tracking (sends initial 0 progress)
     */
    start: () => {
      currentStep = 0;
      sendProgress(progressToken, currentStep, totalSteps);
    },

    /**
     * Increment progress by one step
     */
    increment: () => {
      currentStep++;
      sendProgress(progressToken, currentStep, totalSteps);
    },

    /**
     * Set progress to a specific step
     */
    setProgress: (step: number) => {
      currentStep = step;
      sendProgress(progressToken, currentStep, totalSteps);
    },

    /**
     * Mark operation as complete (sends total progress)
     */
    complete: () => {
      currentStep = totalSteps;
      sendProgress(progressToken, currentStep, totalSteps);
    },

    /**
     * Get current progress state
     */
    getProgress: () => ({
      current: currentStep,
      total: totalSteps,
      percentage: Math.round((currentStep / totalSteps) * 100)
    })
  };
}
