const fs = require("fs");
const path = require("path");

const baseDir = "./"; // Sesuaikan dengan nama direktori utama
const outputFilePath = "./themaderfakerholyjules.txt";

// Daftar file dan folder yang akan diabaikan
const excludeFiles = [
  "package-lock.json",
  ".gitignore",
  "README.md",
  "tailwind.config.js",
  "postcss.config.js",
  "babel.config.js",
  "Makefile",
  "tmp.txt",
  "run.sh",
  "go.sum",
  "prober.log",
  "sniffer_pipe.pid",
  "sniffer_pipeline.log",
  "out.csv",
  "out_x.csv",
  "sum.js",
];
const excludeFolders = [
  "node_modules",
  ".git",
  "assets",
  "bin",
  "logs",
  "verify",
  "resource",
  "build",
  "tmp",
  ".venv",
  "logs",
  "resources",
  "pcap",
  "logs",
  ".vscode",
];

function mergeFiles(directory) {
  fs.readdir(directory, (err, files) => {
    if (err) {
      return console.log("Unable to scan directory: " + err);
    }

    files.forEach((file) => {
      const filePath = path.join(directory, file);
      const stat = fs.lstatSync(filePath);

      // Cek apakah ini folder yang harus diabaikan
      if (stat.isDirectory() && !excludeFolders.includes(file)) {
        // Jika folder bukan di daftar yang dikecualikan, rekursi untuk membaca isinya
        mergeFiles(filePath);
      } else if (stat.isFile() && !excludeFiles.includes(file)) {
        // Jika file bukan di daftar yang dikecualikan, baca isinya dan append ke output file

        // Tulis nama file di atas konten
        fs.appendFileSync(outputFilePath, `\n===== File: ${filePath} =====\n`);

        const fileContent = fs.readFileSync(filePath, "utf-8");
        fs.appendFileSync(outputFilePath, fileContent);

        // Tulis separator untuk memisahkan file
        fs.appendFileSync(outputFilePath, `\n===== End of ${filePath} =====\n`);
      }
    });
  });
}

// Mulai proses penggabungan file dari direktori backend
fs.writeFileSync(
  outputFilePath,
  "Merged Files Output\n=====================\n",
); // Menulis header ke file output
mergeFiles(baseDir);

console.log(
  `All files from ${baseDir} have been merged into ${outputFilePath}`,
);
