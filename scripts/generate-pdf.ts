import { generateExecutivePdfReport } from '../src/utils/pdf-generator.ts';
import { TARGET_PRESETS } from '../src/core/presets.ts';
import fs from 'node:fs';
import path from 'node:path';

async function main() {
  const preset = TARGET_PRESETS[0];
  console.log(`Generating Executive PDF Report for ${preset.name} (${preset.url})...`);

  const pdfBytes = await generateExecutivePdfReport(preset.result);
  const outPath = path.resolve('WebScan-Sample-Executive-Report.pdf');
  fs.writeFileSync(outPath, pdfBytes);

  console.log(`Successfully generated PDF report (${pdfBytes.length} bytes):`);
  console.log(outPath);
}

main().catch(err => {
  console.error('Error generating PDF:', err);
  process.exit(1);
});
