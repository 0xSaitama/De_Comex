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

  const address = "0x36053e79F719C3a09A4D84d11A273aA3B4874d04";

  const abi = ["function faucet(uint256 amount)"];

  const contract = await ethers.getContractAt(abi,address, signers[0]);
  //await contract.deployed();

  console.log("Contract deployed to:", contract.address);

  const tx = await contract.faucet(1_000_000_000);

  //const tx = await contract.populateTransaction.source(source);
  //const txSended = await wallet.sendTransaction(tx);

  await tx.wait();
  console.log(tx);

  console.log("Source code updated tx: ", tx.hash);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
