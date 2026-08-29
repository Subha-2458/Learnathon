import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		include: ['src/server/**/*.test.ts', 'src/lib/**/*.test.ts'],
		fileParallelism: false
	}
});
