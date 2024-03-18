const proposalID = args[0];
const spaceID = args[1];

if (!proposalID || !spaceID) {
  throw Error("Proposal ID & spaceID are required");
}

const config = {
  url: "https://hub.snapshot.org/graphql/",
  method: "POST",
  headers: {
    "content-type": "application/json",
  },
  data: {
    query: ` { \
            proposal(id: "${proposalID}") { \
                    id \
                    ipfs \
                    author \
                    space { \
                        id\
                     } \
                    network \
                    body \
                    quorum \
                    state \
                    scores \
                    scores_total \
                } \
            }`,
  },
};

const request = () => Functions.makeHttpRequest(config);

// Execute the API request (Promise)
const { data, error } = await request();
if (error) {
  throw Error("Request failed: " + error);
}

if (data.Response === "Error") {
  console.error(data.Message);
  throw Error(`Functional error. Read message: ${data.Message}`);
}

const { state, totalScore, space, quorum, body, scores, choices } =
  data.data.proposal;

if (space.id !== spaceID) {
  throw Error("wrong space ID");
}

if (state !== "closed") {
  throw Error("Vote not ended");
}

if (totalScore < quorum) {
  return Functions.encodeString("Quorum not met");
}

const highestIndex = scores.indexOf(Math.max(...scores));

const txHash = body.split("`\\\\`");

if (txHash.length !== scores.length + 1) {
  throw Error("wrong number of hash/choices");
}
const hexString = txHash[highestIndex + 1].slice(2)
const bytes = new Uint8Array(hexString.length / 2);
for (let i = 0; i < hexString.length; i += 2) {
  bytes[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
}
return bytes;