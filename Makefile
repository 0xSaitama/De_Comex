build               :; forge build --names --sizes
clean               :; forge clean
testq               :; forge test
testd               :; forge test -vvvv
testv               :; forge test -vvvvv
testvg              :; forge test -vvvvv --gas-report
install_ds          :; forge install ds-test
install_op          :; forge install https://github.com/OpenZeppelin/openzeppelin-contracts
clean_build         :; forge clean && forge install && forge build
clean_test          :; forge clean && forge test
flatten				:; forge flatten --output output/APIAccount_flat.sol contracts/APIAccount.sol
sol2uml  			:; sol2uml ./output -o ./smart-contract_architecture.svg -b APIAccount
lcov				:; forge coverage --report lcov && lcov --remove lcov.info 'node_modules/*' 'src/*' 'test/*' 'contracts/mocks/*' 'contracts/Libraries/*' -o lcov_parsed.info && genhtml lcov_parsed.info -o report --branch-coverage && open report/index.html
format				:; forge fmt && forge fmt ./contracts/ && forge fmt ./scripts/
ci					:; forge fmt --check && forge fmt ./contracts/ --check && make lfg && forge snapshot --nmt invariant --check --tolerance 1 && forge test --mt invariant
storage				:; forge inspect CollectioADel storage-layout --pretty
chisel				:; chisel --use ~/.svm/0.8.20/solc-0.8.20
snapshot			:; forge snapshot --nmt invariant
deploySM			:; forge script ./scripts/SnapshotModule.deploy.s.sol --rpc-url  --private-key  --slow --broadcast -vvvvv
deployAA			:; forge script ./scripts/APIAccount.deploy.s.sol --rpc-url  --private-key  --slow --broadcast -vvvvv
setModuleAA			:; forge script ./scripts/APIAccount.setModule.s.sol --rpc-url  --private-key  --slow --broadcast -vvvvv
requestAA			:; forge script ./scripts/APIAccount.request.s.sol --rpc-url  --private-key  --slow --broadcast -vvvvv
executeAA			:; forge script ./scripts/APIAccount.execute.s.sol --rpc-url  --private-key  --slow --broadcast -vvvvv
debugAA				:; forge script ./scripts/APIAccount.debug.s.sol --rpc-url  --private-key  --slow --broadcast -vvvvv
debugSM				:; forge script ./scripts/SnapshotModule.debug.s.sol --rpc-url  --private-key  --slow --broadcast -vvvvv
faucet				:; forge script ./scripts/MockERC20.faucet.s.sol --rpc-url  --private-key  --slow --broadcast -vvvvv