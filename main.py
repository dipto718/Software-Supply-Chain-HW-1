import argparse
import json
import requests
import os
import base64
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

# retrns the log entry in json format
def get_log_entry(log_index, debug=False):

    # from the rekor api /api/v1/log/entries is used to get the
    # log entry by logindex
    #?logindex= is needed as otherwise going to https://rekor.sigstore.dev/api/v1/log/entries
    # gives code 602 and states how the logindex is needed for the query to be done
    # constructs the rl for the request
    request_url = "https://rekor.sigstore.dev/api/v1/log/entries?logIndex="
    request_url += str(log_index)
    # verify that log index value is sane and returns the log entry if it is
    # this is determined by the status code for the request as a status >= 400
    # indicates that the request was a failure and therefore raise_for_status
    # from the request import would raise an exception
    data = requests.get(request_url)
    data.raise_for_status()
    # if there was no exception, converts the data to a json
    # format and returns it
    return data.json()

# returns the inculsion proof
def get_verification_proof(log_index, debug=False):
   
    # gets the log entry in json format
    data_json = get_log_entry(log_index)
    # returns the proof
    return ((list(data_json.values())[0])["verification"]["inclusionProof"])
    
# verifies inclsion
def inclusion(log_index, artifact_filepath, debug=False):
    # gets the log entry in json format
    data_json = get_log_entry(log_index)

    # verify that the artifact filepath is sane
    # its not sane if either the artifact doesn't exist
    # or if its not a valid file
    if ((os.path.exists(artifact_filepath) and os.path.isfile(artifact_filepath)) != True):
        print("The filepath is not sane")
        return

    # the raw body needs to be decoded first as it contains the signature 
    # as can be seen by the file stucture on search.sigstore.dev
    # it then needs to be made into json again for ease of use
    list_body = list(data_json.values())[0]
    body = list_body.get("body")
    body_decode = json.loads(base64.b64decode(body))

    # gets the signature and decodes it
    sig = body_decode["spec"]["signature"]["content"]
    sig_decoded = base64.b64decode(sig)

    # gets the certificate and decodes it
    cert = body_decode["spec"]["signature"]["publicKey"]["content"]
    cert_decoded = base64.b64decode(cert)

    # extract_public_key(certificate)
    # extracts the public key from the certificate
    pk = extract_public_key(cert_decoded)

    # verify_artifact_signature(signature, public_key, artifact_filepath)
    # verifies that the signature is valid
    verify_artifact_signature(sig_decoded, pk, artifact_filepath)

    
    # get_verification_proof(log_index)
    # gets the inclusion proof
    ver_proof = get_verification_proof(log_index)

    # gets the leaf hash which is calculated with
    # the original body as compute_leaf_hash does the decoding itself
    leaf_hash = compute_leaf_hash(body)

    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    # verifies inclusion
    verify_inclusion(DefaultHasher, ver_proof["logIndex"], ver_proof["treeSize"], leaf_hash, ver_proof["hashes"], ver_proof["rootHash"])
    print("Offline root hash calculation for inclusion verified")
    
# gets the latest checkpoint
def get_latest_checkpoint(debug=False):
    # from the rekor api /api/v1/log is used to get the current state
    # of the transparency log aka the latest checkpoint

    # the latest checkpoint can be gotten at this url according
    # to the api specifications
    request_url = "https://rekor.sigstore.dev/api/v1/log/"

    # gets the checkpoint from the api and converts it to
    # a json format so that it can be displayed when
    # python main.py -c is done
    data = requests.get(request_url).json()

    # returns the checkpoint
    return data

# verifies whether a previous checkpoint is consitent with
# the current one
def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    if len(prev_checkpoint) == 0:
        print("previous checkpoint is empty")
        return

    # get_latest_checkpoint() so as to later
    # extract its tree size
    curr_checkpoint = get_latest_checkpoint()

    # builds the url request for the proof
    request_url = "https://rekor.sigstore.dev/api/v1/log/proof?firstSize="
    request_url += str(prev_checkpoint["treeSize"])
    lastSize = curr_checkpoint["treeSize"]
    request_url += "&lastSize="
    request_url += str(lastSize)
    request_url += "&treeID="
    request_url += prev_checkpoint["treeID"]

    # gets the proof
    proof = (requests.get(request_url).json())["hashes"]

    # extracts the other root hash from the current checkpoint
    root2 = curr_checkpoint["rootHash"]

    # uses the default hasher
    # verifies consistency with the function provided
    # in the template
    verify_consistency(DefaultHasher, prev_checkpoint["treeSize"] , lastSize, proof, prev_checkpoint["rootHash"], root2)
    # if no mismatch errors were raised then the previous checkpoint is consistent
    # with the current one
    print("Consistency verification successful")

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
