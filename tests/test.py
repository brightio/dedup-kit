#!/usr/bin/python3

import os
import shutil
import tempfile
import unittest

from dedup_kit import DupFinder

FILE_SIZE = 500_000_000

class TestDups(unittest.TestCase):

	def setUp(self):

		self.parent_dir = tempfile.mkdtemp()

		os.makedirs(f"{self.parent_dir}/testdir1", exist_ok=True)
		os.makedirs(f"{self.parent_dir}/testdir2", exist_ok=True)

		with open(f"{self.parent_dir}/testdir1/AAA", "wb") as f:
			f.write(b'A' * FILE_SIZE)

		with open(f"{self.parent_dir}/testdir2/AAA", "wb") as f:
			f.write(b'A' * FILE_SIZE)

		with open(f"{self.parent_dir}/testdir1/BBB", "wb") as f:
			f.write(b'A' * (FILE_SIZE - 1000))
			f.write(b'B' * 1000)

		with open(f"{self.parent_dir}/testdir2/BBB", "wb") as f:
			f.write(b'A' * (FILE_SIZE - 1000))
			f.write(b'B' * 1000)

		with open(f"{self.parent_dir}/testdir1/CCC", "wb") as f:
			f.write(b'B' * 100)
			f.write(b'A' * (FILE_SIZE - 1000))

		with open(f"{self.parent_dir}/testdir2/CCC", "wb") as f:
			f.write(b'B' * 100)
			f.write(b'A' * (FILE_SIZE - 1000))

	def tearDown(self):
		shutil.rmtree(self.parent_dir)

	def test_basic(self):
		correct_pairs = [
			sorted([f'{self.parent_dir}/testdir2/AAA', f'{self.parent_dir}/testdir1/AAA']),
			sorted([f'{self.parent_dir}/testdir2/BBB', f'{self.parent_dir}/testdir1/BBB']),
			sorted([f'{self.parent_dir}/testdir2/CCC', f'{self.parent_dir}/testdir1/CCC'])
		]

		self.assertEqual(
			[sorted(file.path for file in dup.files) for dup in DupFinder([self.parent_dir]).get_dupes()[0]],
			correct_pairs
		)

if __name__ == "__main__":
	unittest.main()
