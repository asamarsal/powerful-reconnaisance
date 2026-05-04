/**
 * Rate Limiter - Controls request rate to avoid IP bans
 */
export class RateLimiter {
  constructor(maxPerSecond = 10, maxConcurrent = 5) {
    this.maxPerSecond = maxPerSecond;
    this.maxConcurrent = maxConcurrent;
    this.queue = [];
    this.running = 0;
    this.timestamps = [];
  }

  async acquire() {
    return new Promise((resolve) => {
      const tryAcquire = () => {
        const now = Date.now();
        // Clean old timestamps
        this.timestamps = this.timestamps.filter(t => now - t < 1000);

        if (this.running < this.maxConcurrent && this.timestamps.length < this.maxPerSecond) {
          this.running++;
          this.timestamps.push(now);
          resolve();
        } else {
          setTimeout(tryAcquire, 100);
        }
      };
      tryAcquire();
    });
  }

  release() {
    this.running--;
  }

  async execute(fn) {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  async executeAll(tasks, fn) {
    return Promise.all(tasks.map(task => this.execute(() => fn(task))));
  }
}

export default RateLimiter;
