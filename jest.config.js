module.exports = {
  testEnvironment: 'node',
  verbose: true,
  testMatch: ['**/__tests__/**/*.test.js', '**/tests/**/*.test.js'],
  testPathIgnorePatterns: ['/node_modules/', '/coverage/'],
  collectCoverage: true,
  collectCoverageFrom: [
    'server.js',
    'security.js',
    'database.js',
    '!**/node_modules/**'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov'],
  testTimeout: 15000
};