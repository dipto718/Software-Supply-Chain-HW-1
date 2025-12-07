"""test cases"""

import os
import sys
import subprocess
import json
from jsonschema import validate
import main

curr_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(curr_dir)
sys.path.append(parent_dir)

# import merkle_proof
# import util

checkpoint = {
    "type": "object",
    "properties": {
        "inactiveShards": {"type": "array"},
        "rootHash": {"type": "string"},
        "signedTreeHead": {"type": "string"},
        "treeID": {"type": "string"},
        "treeSize": {"type": "integer"},
    },
    "required": ["inactiveShards", "rootHash", "signedTreeHead", "treeID", "treeSize"],
}


# case 0
# the example test that was given
# doesn't seem to count
# in the coverage report for main.py
# tests -c
# def test_checkpoint():
#     """test 0"""
#     result = subprocess.run(
#         ["python3", "main.py", "-c"], capture_output=True, text=True
#     )

#     output = result.stdout
#     data = json.loads(output)

#     validate(instance=data, schema=checkpoint)


# case 1
# tests that getting the latest
# checkpoint works
def test_checkpoint_by_function():
    """test 1"""
    result = main.get_latest_checkpoint()
    validate(instance=result, schema=checkpoint)


# case 2
# main should sucessfully exit with an error code
# as argumentparser gets no args to parse
# if main() is called directly rather than adding
# the args on the command line with python main.py [commands]
def test_main():
    """test 2"""
    try:
        main.main()
        assert False
    except SystemExit:
        assert True


# case 3
# makes sure that the
# consistency check works with
# a valid input
# if it works, it should
# not raise any exception
def test_consistency():
    """test 3"""
    prev_checkpoint = {}
    prev_checkpoint["treeID"] = 1193050959916656506
    prev_checkpoint["treeSize"] = 566822630
    prev_checkpoint["rootHash"] = (
        "6e9b436995ed0978ea0acc8d86dc8375c08c7c0e2c8e62cc5fe4285fe63a024f"
    )
    try:
        main.consistency(prev_checkpoint)
        assert True
    except SystemExit:
        assert False


# case 4
# makes sure that the
# inclusion check works with
# a valid input
# if it works, it should
# not raise any exception
def test_inclusion():
    """test 4"""
    try:
        main.inclusion(547323620, "artifact.md")
        assert True
    except SystemExit:
        assert False


# case 5
# makes sure that the
# inclusion check fails with
# an invalid input
# it should raise an exception
def test_inclusion_invalid_logindex():
    """test 5"""
    try:
        main.inclusion(54732362000000000, "artifact.md")
        assert False
    except SystemExit:
        assert True


# case 6
# makes sure that the
# consistency check fails with
# an invalid input
# it should raise an exception
def test_consistency_invalid_root_hash():
    """test 6"""
    prev_checkpoint = {}
    prev_checkpoint["treeID"] = 1193050959916656506
    prev_checkpoint["treeSize"] = 566822630
    prev_checkpoint["rootHash"] = (
        "709ghghb436995ed0978ea0acc8d86dc8375c08c7c0e2c8e62cc5fe4285fe63a024f"
    )
    try:
        main.consistency(prev_checkpoint)
        assert False
    except SystemExit:
        assert True


# case 7
# makes sure that the
# consistency check fails with
# an invalid input
# it should raise an exception
def test_consistency_invalid_tree_size():
    """test 7"""
    prev_checkpoint = {}
    prev_checkpoint["treeID"] = 1193050959916656506
    prev_checkpoint["treeSize"] = 5668226300000000000
    prev_checkpoint["rootHash"] = (
        "6e9b436995ed0978ea0acc8d86dc8375c08c7c0e2c8e62cc5fe4285fe63a024f"
    )
    try:
        main.consistency(prev_checkpoint)
        assert False
    except SystemExit:
        assert True


# case 8
# makes sure that the
# consistency check fails with
# an invalid input
# it should raise an exception
def test_consistency_invalid_tree_id():
    """test 8"""
    prev_checkpoint = {}
    prev_checkpoint["treeID"] = 119305095991665650600000000000
    prev_checkpoint["treeSize"] = 566822630
    prev_checkpoint["rootHash"] = (
        "6e9b436995ed0978ea0acc8d86dc8375c08c7c0e2c8e62cc5fe4285fe63a024f"
    )
    try:
        main.consistency(prev_checkpoint)
        assert False
    except SystemExit:
        assert True


# case 9
# makes sure that the
# inclusion check fails with
# an invalid input
# it should raise an exception
def test_inclusion_invalid_unsigned_artifact():
    """test 9"""
    try:
        main.inclusion(547323620, "artifact.bundle")
        assert False
    except Exception:
        assert True


# case 10
# makes sure that the
# consistency check works with
# a valid empty input
# if it works, it should
# not raise any exception
# as it returns nothing rather than
# raising an exception
def test_consistency_empty_checkpoint():
    """test 10"""
    prev_checkpoint = {}
    try:
        main.consistency(prev_checkpoint)
        assert True
    except SystemExit:
        assert False
