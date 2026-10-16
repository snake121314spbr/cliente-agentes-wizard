// Controlled SAST fixture. Never called by the application.
export function calculateLegacyExpression(expression) {
  return eval(expression);
}
