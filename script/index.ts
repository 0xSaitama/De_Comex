import { ethers } from "hardhat";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
dotenv.config({path: '.env'});

async function main() {
  const source = fs
    .readFileSync(path.resolve(__dirname, "source.js"))
    .toString();

  let signers = await ethers.getSigners();

  const address = "0x82918310390E0739F0D869E907c76306a8b0901E";

  const abi = ["function setSource(string memory _source)"];

  const contract = await ethers.getContractAt(abi,address, signers[0]);
  //await contract.deployed();

  console.log("Contract deployed to:", contract.address);

  const tx = await contract.setSource(source);

  //const tx = await contract.populateTransaction.source(source);
  //const txSended = await wallet.sendTransaction(tx);

  await tx.wait();

  console.log("Source code updated tx: ", tx.hash);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
