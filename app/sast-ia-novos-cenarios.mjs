// LAB ONLY: intentionally unsafe source for SAST. Do not import into a live app.
// Functions are never called here. No server, credentials or external requests on load.
import { exec } from 'node:child_process';
import { readFile } from 'node:fs/promises';
export function searchCustomers(req, db) {
  return db.query("SELECT id FROM customers WHERE name = '" + req.query.name + "'");
}
export function convertDocument(req, res) {
  exec('convert ' + req.body.filename, (error, output) => res.end(output));
}
export async function previewRemoteDocument(req, res) {
  const target = req.body.documentUrl;
  const upstream = await fetch(target);
  res.end(await upstream.text());
}
export async function downloadReport(req, res) {
  const reportPath = '/srv/customer-reports/' + req.query.filename;
  res.end(await readFile(reportPath));
}
export async function viewInvoice(req, res, db) {
  const invoice = await db.getInvoice(req.params.invoiceId);
  res.end(JSON.stringify(invoice));
}
export async function updateMyProfile(req, res, db) {
  const changes = { ...req.body };
  const user = await db.updateUser(req.user.id, changes);
  res.end(JSON.stringify(user));
}
export async function refundOrder(req, res, db) {
  const order = await db.getOrder(req.body.orderId);
  await db.creditBalance(req.user.id, order.total);
  await db.markRefunded(order.id);
  res.end('Refund accepted');
}
