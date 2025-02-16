import fs from "fs";
import path from "path";
import dotenv from "dotenv";
dotenv.config({path: '.env'});

async function main() {
  const source = fs
    .readFileSync(path.resolve(__dirname, "../script/source.js"))
    .toString();

  console.log("Source code:");
  console.log(source);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
