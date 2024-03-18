import dotenv from "dotenv";
import { ethers } from "ethers";
dotenv.config({path: '.env'});

async function main() {
  const functionName = "transfer";
  const argTypes = ["address", "uint256"];
  const args = ["0xDDf86597aFF5c826643BCed8eF0b84b10a2847aB", "1000000"];
  const valueToSend = "0";
  const addressToCall = "0x36053e79F719C3a09A4D84d11A273aA3B4874d04";

  const selector = ethers.utils.id(`${functionName}(${argTypes.join(",")})`).slice(0, 10);
  const encodedArgs = ethers.utils.defaultAbiCoder.encode(argTypes, args).slice(2);

  const data = selector + encodedArgs;
  const transaction = {
    to: addressToCall,
    data: data,
    value: ethers.utils.parseEther(valueToSend),
  };
  console.log(transaction);

  const encodedTransaction = ethers.utils.defaultAbiCoder.encode(["tuple(address to, bytes data, uint256 value)"], [transaction]);
  const hash = ethers.utils.id(encodedTransaction);
  console.log(hash);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
