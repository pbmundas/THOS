import fs from "node:fs/promises";
import path from "node:path";
import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";

const inputPath = "C:/Users/Prasanna/Downloads/IOC sources.xlsx";
const outputDir = path.resolve(".");
const input = await FileBlob.load(inputPath);
const workbook = await SpreadsheetFile.importXlsx(input);

const summary = await workbook.inspect({
  kind: "workbook,sheet,table",
  include: "id,name,values,formulas",
  maxChars: 12000,
  tableMaxRows: 20,
  tableMaxCols: 20,
  tableMaxCellChars: 240,
});
console.log("SUMMARY");
console.log(summary.ndjson);

for (const sheet of workbook.worksheets.items) {
  const used = sheet.getUsedRange();
  const details = await workbook.inspect({
    kind: "region,computedStyle",
    sheetId: sheet.name,
    range: used?.address || "A1:Z100",
    include: "values,formulas",
    maxChars: 30000,
    tableMaxRows: 200,
    tableMaxCols: 30,
    tableMaxCellChars: 500,
  });
  console.log(`SHEET ${sheet.name}`);
  console.log(details.ndjson);
  const safeName = sheet.name.replace(/[^A-Za-z0-9_.-]+/g, "_");
  const values = sheet.getRange(used?.address || "A1:F133").values;
  const headers = values[0];
  const sources = values.slice(1).map((row) =>
    Object.fromEntries(
      headers.map((header, index) => [String(header), row[index] ?? null]),
    ),
  );
  await fs.writeFile(
    path.join(outputDir, `${safeName}-sources.json`),
    JSON.stringify({ sheet: sheet.name, range: used?.address, sources }, null, 2),
    "utf8",
  );

  const renderRanges = ["A1:F45", "A46:F90", "A91:F133"];
  for (const [index, range] of renderRanges.entries()) {
    const preview = await workbook.render({
      sheetName: sheet.name,
      range,
      scale: 1.15,
      format: "png",
    });
    await fs.writeFile(
      path.join(outputDir, `${safeName}-${index + 1}.png`),
      new Uint8Array(await preview.arrayBuffer()),
    );
  }
}
