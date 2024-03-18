import { config as dotEnvConfig } from "dotenv";
import '@nomiclabs/hardhat-waffle'
import '@nomiclabs/hardhat-ethers'
dotEnvConfig();

import { HardhatUserConfig } from "hardhat/config";

const log = console.log;

// const INFURA_API_KEY = process.env.INFURA_API_KEY || "";
// const ROPSTEN_PRIVATE_KEY = process.env.ROPSTEN_PRIVATE_KEY || "";
// const RINKEBY_PRIVATE_KEY = process.env.RINKEBY_PRIVATE_KEY || "";
const LOCALHOST_PRIVATE_KEY = process.env.LOCALHOST_PRIVATE_KEY || "";
const PRIVATE_KEY = process.env.PRIVATE_KEY || "";
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY;
const COINMARKETCAP_API_KEY = process.env.COINMARKETCAP_API_KEY || "";
// const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY || '';

const config: HardhatUserConfig = {
  // ovm: {
  //   solcVersion: "0.8.4",
  // },
  defaultNetwork: "hardhat",
  paths: {
    sources: "./contracts",
  },
  solidity: {
    compilers: [
      {
        version: "0.8.19",
        settings: {
          outputSelection: {
            "*": {
              "*": ["storageLayout"],
            },
          },
          optimizer: { enabled: true, runs: 1 },
        },
      },
    ],
  },
  networks: {
    hardhat: {
      gas: 12000000,
      blockGasLimit: 0x1fffffffffffff, // defaultValue: 12450000
      allowUnlimitedContractSize: true,
      chainId: 1,
      initialBaseFeePerGas: 0,
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      // accounts: [LOCALHOST_PRIVATE_KEY],
    },
    sepolia: {
      url: 'https://sepolia.infura.io/v3/3da10ed8e1234a27b05c734ce2dfe47e',
      accounts: [PRIVATE_KEY],
    },
    // rinkeby: {
    //   url: `https://rinkeby.infura.io/v3/${INFURA_API_KEY}`,
    //   accounts: [RINKEBY_PRIVATE_KEY],
    // },
  },
  // docgen: {
  //   path: "./docs",
  //   clear: true,
  //   runOnCompile: true,
  // },

};

export default config;