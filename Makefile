build               :; forge build --names --sizes
clean               :; forge clean
testq               :; forge test
testd               :; forge test -vvvv
testv               :; forge test -vvvvv
testvg              :; forge test -vvvvv --gas-report
install_ds          :; forge install ds-test
install_op          :; forge install https://github.com/OpenZeppelin/openzeppelin-contracts
lfg                 :; forge clean && forge install && forge build
buidl               :; forge clean && forge test
lcov				:; forge coverage --report lcov && lcov --remove lcov.info 'node_modules/*' 'src/*' 'test/*' 'contracts/mocks/*' 'contracts/Libraries/*' -o lcov_parsed.info && genhtml lcov_parsed.info -o report --branch-coverage && open report/index.html
format				:; forge fmt && forge fmt ./contracts/ && forge fmt ./scripts/
ci					:; forge fmt --check && forge fmt ./contracts/ --check && make lfg && forge snapshot --nmt invariant --check --tolerance 1 && forge test --mt invariant
storage				:; forge inspect CollectioADel storage-layout --pretty
chisel				:; chisel --use ~/.svm/0.8.20/solc-0.8.20
snapshot			:; forge snapshot --nmt invariant