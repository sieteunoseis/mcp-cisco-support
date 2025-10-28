/**
 * Progress Notification Utilities
 *
 * Provides progress notification functionality for long-running MCP tool operations.
 * Sends notifications/progress messages to clients that support them.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { logger } from './logger.js';

// Global MCP server instance for progress notifications
let mcpServerInstance: Server | null = null;

/**
 * Initialize the progress notification system with an MCP server instance
 * @param server - The MCP server instance to use for notifications
 */
export function initializeProgressNotifications(server: Server): void {
  mcpServerInstance = server;
  logger.info('Progress notifications initialized');
}

/**
 * Send a progress notification to the client
 *
 * @param progressToken - Optional progress token from the client request
 * @param progress - Current progress value (e.g., 1, 2, 3)
 * @param total - Total number of steps (e.g., 5)
 *
 * @example
 * ```typescript
 * // Multi-step operation
 * sendProgress(meta?.progressToken, 0, 5); // Starting
 * sendProgress(meta?.progressToken, 1, 5); // 20% complete
 * sendProgress(meta?.progressToken, 2, 5); // 40% complete
 * sendProgress(meta?.progressToken, 5, 5); // 100% complete
 * ```
 */
export function sendProgress(
  progressToken: string | undefined,
  progress: number,
  total: number
): void {
  if (!progressToken || !mcpServerInstance) {
    // Client didn't request progress or server not initialized
    // Silently skip - this is normal for clients that don't support progress
    return;
  }

  try {
    mcpServerInstance.notification({
      method: 'notifications/progress',
      params: {
        progressToken,
        progress,
        total
      }
    });

    const percentage = Math.round((progress / total) * 100);
    logger.info('Progress notification sent', {
      progressToken: progressToken.substring(0, 8) + '...',
      progress,
      total,
      percentage: `${percentage}%`
    });
  } catch (error) {
    logger.error('Failed to send progress notification', {
      error: error instanceof Error ? error.message : error,
      progress,
      total
    });
  }
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

/**
 * Check if progress notifications are supported/enabled
 * @returns True if progress notifications can be sent
 */
export function canSendProgress(): boolean {
  return mcpServerInstance !== null;
}
