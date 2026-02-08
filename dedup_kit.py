#!/usr/bin/env python3

# Copyright © 2024 @brightio <brightiocode@gmail.com>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__program__ = "dedup"
__version__ = "0.8.1"

import os
import re
import sys
import time
import signal
import logging
import argparse
import subprocess

from pathlib import Path
from functools import partial
from hashlib import md5, blake2b
from datetime import timedelta
from collections import defaultdict
from threading import Thread, RLock, current_thread
from multiprocessing import JoinableQueue, Event, Pool

CHUNK_SIZE = 4 * 1024 * 1024 # 4MB
REPORT_EVERY = 32 * 1024 * 1024 # 16MB
MAX_OPEN_DIRS = 5
HASH_FUNC = blake2b
MAX_JOBS = 10
stop = Event()
verbose = False

# ─────────────────────────────── <PYTHON MISSING BATTERIES> ───────────────────────────────
min_version = "3.6"
if sys.version_info < tuple(map(int, min_version.split('.'))) :
	print(f"(!) <{__program__}> requires Python version {min_version} or higher (!)")
	sys.exit(1)

class paint:
	_codes = {'RESET':0, 'BRIGHT':1, 'DIM':2, 'UNDERLINE':4, 'BLINK':5, 'NORMAL':22}
	_colors = {'black':0, 'red':1, 'green':2, 'yellow':3, 'blue':4, 'magenta':5, 'cyan':6, 'white':7, 'orange':136}
	_escape = lambda codes: f"\x1b[{codes}m"

	def __init__(self, text=None, colors=None):
		self.text = str(text) if text is not None else None
		self.colors = colors if colors is not None else []

	def __str__(self):
		if self.colors:
			content = self.text + __class__._escape(__class__._codes['RESET']) if self.text is not None else ''
			return __class__._escape(';'.join(self.colors)) + content
		return self.text

	def __len__(self):
		return len(self.text)

	def __add__(self, text):
		return str(self) + str(text)

	def __mul__(self, num):
		return __class__(self.text * num, self.colors)

	def __getattr__(self, attr):
		self.colors.clear()
		for color in attr.split('_'):
			if color in __class__._codes:
				self.colors.append(str(__class__._codes[color]))
			else:
				prefix = "3" if color in __class__._colors else "4"
				self.colors.append(prefix + "8;5;" + str(__class__._colors[color.lower()]))
		return self


class CustomFormatter(logging.Formatter):
	TEMPLATES = {
		logging.CRITICAL:	{'color':"RED_BLINK",	'prefix':"[!!!]"},
		logging.ERROR:		{'color':"red",		'prefix':"[-]"},
		logging.WARNING:	{'color':"yellow",	'prefix':"[!]"},
		logging.INFO:		{'color':"green",	'prefix':"[+]"},
		logging.DEBUG:		{'color':"magenta",	'prefix':"[---DEBUG---]"}
	}
	def format(self, record):
		template = __class__.TEMPLATES[record.levelno]
		text = f"{template['prefix']} {logging.Formatter.format(self, record)}"
		return str(getattr(paint(text), template['color']))

class PBar:
	pbars = []

	def __init__(self, end, caption="", barlen=None, queue=None, metric=None):
		self.end = end
		if type(self.end) is not int: self.end = len(self.end)
		self.active = True if self.end > 0 else False
		self.pos = 0
		self.percent = 0
		self.caption = caption
		self.bar = '#'
		self.barlen = barlen
		self.percent_prev = -1
		self.queue = queue
		self.metric = metric
		self.check_interval = 1
		if self.queue: self.trace_thread = Thread(target=self.trace); self.trace_thread.start(); __class__.render_lock = RLock()
		if self.metric: Thread(target=self.watch_speed, daemon=True).start()
		else: self.metric = lambda x: f"{x:,}"
		__class__.pbars.append(self)
		print("\x1b[?25l", end='', flush=True)
		self.render()

	def __bool__(self):
		return self.active

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		self.terminate()

	def trace(self):
		while True:
			data = self.queue.get()
			self.queue.task_done()
			if isinstance(data, int): self.update(data)
			elif data is None: break
			else: self.print(data)

	def watch_speed(self):
		self.pos_prev = 0
		self.elapsed = 0
		while self:
			time.sleep(self.check_interval)
			self.elapsed += self.check_interval
			self.speed = self.pos - self.pos_prev
			self.pos_prev = self.pos
			self.speed_avg = self.pos / self.elapsed
			if self.speed_avg: self.eta = int(self.end / self.speed_avg) - self.elapsed
			if self: self.render()

	def update(self, step=1):
		if not self: return False
		self.pos += step
		if self.pos >= self.end: self.pos = self.end
		self.percent = int(self.pos * 100 / self.end)
		if self.pos >= self.end: self.terminate()
		if self.percent > self.percent_prev: self.render()

	def render_one(self):
		self.percent_prev = self.percent
		left = f"{self.caption}["
		elapsed = "" if not hasattr(self, 'elapsed') else f" | Elapsed {timedelta(seconds=self.elapsed)}"
		speed = "" if not hasattr(self, 'speed') else f" | {self.metric(self.speed)}/s"
		eta = "" if not hasattr(self, 'eta') else f" | ETA {timedelta(seconds=self.eta)}"
		right = f"] {str(self.percent).rjust(3)}% ({self.metric(self.pos)}/{self.metric(self.end)}){speed}{elapsed}{eta}"
		bar_space = self.barlen or os.get_terminal_size().columns - len(left) - len(right)
		bars = int(self.percent * bar_space / 100) * self.bar
		print(f'\x1b[2K{left}{bars.ljust(bar_space, ".")}{right}\n', end='', flush=True)

	def render(self):
		if hasattr(__class__, 'render_lock'): __class__.render_lock.acquire()
		for pbar in __class__.pbars: pbar.render_one()
		print(f"\x1b[{len(__class__.pbars)}A", end='', flush=True)
		if hasattr(__class__, 'render_lock'): __class__.render_lock.release()

	def print(self, data):
		if hasattr(__class__, 'render_lock'): __class__.render_lock.acquire()
		print(f"\x1b[2K{data}", flush=True)
		self.render()
		if hasattr(__class__, 'render_lock'): __class__.render_lock.release()

	def terminate(self):
		if self.queue and current_thread() != self.trace_thread: self.queue.join(); self.queue.put(None)
		if hasattr(__class__, 'render_lock'): __class__.render_lock.acquire()
		if not self: return
		self.active = False
		if hasattr(self, 'eta'): del self.eta
		if not any(__class__.pbars):
			self.render()
			print("\x1b[?25h" + '\n' * len(__class__.pbars), end='', flush=True)
			__class__.pbars.clear()
		if hasattr(__class__, 'render_lock'): __class__.render_lock.release()

class Size:
	units = ("", "K", "M", "G", "T", "P", "E", "Z", "Y")
	def __init__(self, _bytes):
		self.bytes = _bytes

	def __str__(self):
		index = 0
		new_size = self.bytes
		while new_size >= 1024 and index < len(__class__.units) - 1:
			new_size /= 1024
			index += 1
		return f"{new_size:.1f} {__class__.units[index]}Bytes"

	@classmethod
	def from_str(cls, string):
		if string.isnumeric():
			_bytes = int(string)
		else:
			try:
				num, unit = int(string[:-1]), string[-1]
				_bytes = num * 1024 ** __class__.units.index(unit)
			except:
				logger.error("Invalid size specified")
				sys.exit()
		return cls(_bytes)

def Open(item):
	open_binary = {'linux':'xdg-open','win32':'explorer','darwin':'open'}[sys.platform]
	subprocess.Popen([open_binary, item], stdout=open(os.devnull,'w'), stderr=subprocess.STDOUT)

epoch_to_local = lambda seconds: time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(seconds))
pathlink = lambda filepath: (
	f'\x1b]8;;file://{filepath.parents[0]}\x07{filepath.parents[0]}'
	f'{os.path.sep}\x1b]8;;\x07\x1b]8;;file://{filepath}\x07{filepath.name}\x1b]8;;\x07'
)

def ask(text, readline=False):
	print(text, flush=True, end='')
	answer = ''
	if os.name == 'nt':
		import msvcrt
		if readline:
			answer = input()
		else:
			answer = msvcrt.getwch()
	else:
		import tty, termios, select
		sys.stdin = open('/dev/tty', 'r')
		if readline:
			answer = input()
		else:
			tty_normal = termios.tcgetattr(sys.stdin)
			tty.setraw(sys.stdin)
			rfds = select.select([sys.stdin], [], [])
			answer = os.read(sys.stdin.fileno(), 1024).decode()
			termios.tcsetattr(sys.stdin, termios.TCSADRAIN, tty_normal)
	print("\n", flush=True, end='')
	return answer

def dissect_range(string):
	numbers = []
	for part in string.split(','):
		if '-' in part:
			start, end = part.split('-')
			numbers.extend(range(int(start), int(end) + 1))
		else:
			numbers.append(int(part))
	return tuple(numbers)
# ─────────────────────────────── </PYTHON MISSING BATTERIES> ───────────────────────────────


def init_pool_processes(byte_queue):
	global queue
	queue = byte_queue

class File:
	path_color = {True: 'red', False: 'cyan'}
	def __init__(self, path, _name=None, _dir=None):
		stat = os.lstat(path)
		self.path = path
		self.name = _name or os.path.basename(self.path)
		self.dir = _dir or os.path.dirname(self.path)
		self.hidden = is_hidden(path)
		self.size = stat.st_size
		self._mtime = stat.st_mtime
		self._atime = stat.st_atime
		self.mtime = epoch_to_local(stat.st_mtime)
		self.atime = epoch_to_local(stat.st_atime)
		self.device = stat.st_dev # for evenly distribute in multiprocessing pool
		self.inode = stat.st_ino
		self.hash = ''
		self.basefile = False

	def str(self, index=""):
		_hash = paint(self.hash).magenta
		mdate = paint(self.mtime[:10]).orange
		filepath = getattr(paint(pathlink(Path(self.path))), __class__.path_color[self.basefile])
		output_list = [str(index), str(mdate), str(filepath)]
		if self.hash: output_list.insert(1, str(_hash))
		output = ' '.join(output_list)
		if hasattr(self, 'altpaths'):
			for path in sorted(self.altpaths):
				output += str(paint(f"\n{(len(index) + len(_hash) + len(mdate) + len(output_list) -3) * ' '}↘ {pathlink(Path(path))}").green)
		return output

	def __repr__(self):
		return self.path

	def __hash__(self):
		return hash((self.device, self.inode))

	def __eq__(self, other):
		same = (self.device == other.device and self.inode == other.inode)
		if same and self.path != other.path:
			if not hasattr(self, 'altpaths'):
				self.altpaths = set()
			self.altpaths.add(other.path)
		return same

	def remove(self):
		logger.info(f"Removing: {self.path}")
		try:
			os.remove(self.path)
			if hasattr(self, 'altpaths'):
				for hardlinkpath in sorted(self.altpaths):
					logger.info(f"Removing hard link: {hardlinkpath}")
					try:
						os.remove(hardlinkpath)
					except Exception as e:
						logger.error(e)
		except Exception as e:
			logger.error(e)


def is_hidden(path):
	if os.name == 'nt':
		return bool(os.stat(path).st_file_attributes & 0x02)
	else:
		return os.path.basename(path).startswith('.')

def calculate_hash(file, hashfunc):
	try:
		bytes_read = 0
		sent = 0

		if stop.is_set():
			return None, bytes_read

		if verbose:
			queue.put(f"{file.size}\t{file.path}")

		with open(file.path, "rb") as f:
			_hash = hashfunc()

			while True:
				chunk = f.read(CHUNK_SIZE)
				if not chunk:
					break
				_hash.update(chunk)

				_len = len(chunk)
				bytes_read += _len
				sent += _len

				if sent >= REPORT_EVERY:
					queue.put(sent)
					sent = 0

				if stop.is_set():
					if sent:
						queue.put(sent)
					return None, bytes_read
		if sent:
			queue.put(sent)

		__hash = _hash.hexdigest()
	except Exception as e:
		if sent:
			queue.put(sent)

		queue.put(str(paint(str(e)).red))
		#remaining = file.size - bytes_read
		#if remaining > 0:
		#	queue.put(remaining)

		return None, bytes_read

	return __hash, bytes_read

def calculate_hashes(files_to_read, bytes_to_read, hashfunc):
	byte_queue = JoinableQueue()
	bytes_read = 0
	groups = defaultdict(list)
	partial_calculate_hash = partial(calculate_hash, hashfunc=hashfunc)
	process_num = min(os.cpu_count(), len(files_to_read), MAX_JOBS)
	with Pool(process_num, initializer=init_pool_processes, initargs=(byte_queue,)) as pool,\
		PBar(files_to_read, 'Files read ', 30) as fbar,\
		PBar(bytes_to_read, 'Bytes read ', 30, byte_queue, Size) as bbar:
		for index, (_hash, _bytes_read) in enumerate(pool.imap(partial_calculate_hash, files_to_read)):
			if _hash:
				groups[_hash].append(files_to_read[index])
				fbar.update()
			bytes_read += _bytes_read
		return groups, bytes_read


class Dup:
	def __init__(self, *files, basefiles=()):
		self.files = sorted(files, key=lambda x: x._mtime)
		self.basefiles = sorted(basefiles, key=lambda x: x._mtime)
		for file in self.basefiles:
			file.basefile = True
		self.all_files = self.basefiles + self.files
		self.file_size = files[0].size

	def __str__(self):
		human_readable_size = paint(f"({str(Size(self.file_size))})").white if self.file_size >= 1024 else ''
		output = paint(f"\n↪  {self.file_size:,} bytes {human_readable_size}").red
		if self.basefiles:
			num_len = len(str(len(self.all_files)))
			for index, file in enumerate(self.basefiles, 1):
				index = paint(format(str(index), f">{num_len}") + ')').RED
				output += f"\n{file.str(index)}"

			for file in self.files:
				output += f"\n{file.str((num_len + 1) * ' ')}"
		else:
			num_len = len(str(len(self.files)))
			for index, file in enumerate(self.files, 1):
				index = paint(format(str(index), f">{num_len}") + ')').green
				output += f"\n{file.str(index)}"
		return output

	def __len__(self):
		if not self.basefiles:
			return self.file_size * (len(self.files) - 1)
		else:
			return self.file_size * len(self.basefiles)

	@property
	def duplicate_files(self):
		if not self.basefiles:
			return len(self.files) - 1
		else:
			return len(self.basefiles)

	def info(self):
		for index, file in enumerate(self.all_files, 1):
			print(
				f"\n{paint(f'[{index}] {file.path}').green}\n{paint('Modification time:').cyan}"
				f" {file.mtime}, {paint('Access time:').cyan} {file.atime}"
			)
		print()

	def md5(self):
		groups, _ = calculate_hashes(self.all_files, len(self.all_files) * self.file_size, md5)
		for _hash, files in groups.items():
			for file in files:
				file.hash = _hash

	def verify(self):
		self.md5()
		#self.all_files[1].hash = "XXXXXXXXXXX"
		for file in self.all_files:
			if file.hash != self.all_files[0].hash:
				print()
				logger.critical("False positive duplicate")
				return False
		return True

	def open(self):
		logger.info(f"Opening file: {self.all_files[0].path}")
		Open(self.all_files[0].path)

	def opendir(self):
		dirs = {os.path.dirname(file.path) for file in self.all_files}
		if len(dirs) > MAX_OPEN_DIRS:
			logger.error(f"Maximum directories to open: {MAX_OPEN_DIRS}")
		else:
			for _dir in dirs:
				logger.info(f"Opening directory: {_dir}")
				Open(_dir)

	def remove(self):
		if self.basefiles:
			for basefile in self.basefiles:
				answer = ask(f"Do you want to remove {paint(basefile).green}? [y/n]: ")
				if answer.lower() == 'y':
					basefile.remove()
				else:
					return False
		else:
			try:
				preserve_ids = ask(f"Select the file IDs to preserve [1-{len(self.files)}|[a]ll]: ", readline=True)
				if preserve_ids == 'a':
					logger.info("All files preserved")
					return True
				else:
					preserve_ids = dissect_range(preserve_ids)
				if not 1 <= max(preserve_ids) <= len(self.files):
					raise
				to_remove_ids = [i for i in range(1, len(self.files) + 1) if i not in preserve_ids]
				if not to_remove_ids:
					return True
			except:
				logger.error("Invalid range specification")
				return False
			answer = ask(f"Are you sure you want to remove files with IDs {to_remove_ids}? [y/n]: ")
			if answer.lower() == 'y':
				for i in to_remove_ids:
					self.files[i - 1].remove()
			else:
				return False
		return True


class DupFinder:
	def __init__(
			self,
			items,
			targets=(),
			min_size="1",
			max_size="9Y",
			exclude_files=(),
			exclude_directories=(),
			include_hidden_files=False,
			include_hidden_directories=False,
			sort_size=False
		):

		self.dups = []

		self.items = set(items)
		self.targets = set(targets)
		if self.targets:
			self.unmatched_files = set()

		self.sort_size = sort_size

		# Filtering
		self.min_size = Size.from_str(min_size).bytes
		self.max_size = Size.from_str(max_size).bytes

		self.include_hidden_files = include_hidden_files
		self.include_hidden_directories = include_hidden_directories

		self.exclude_files = exclude_files
		self.exclude_files_patterns = [re.compile(pattern) for pattern in self.exclude_files]

		self.exclude_directories = exclude_directories
		self.exclude_directories_patterns = [re.compile(pattern) for pattern in self.exclude_directories]

		self.specific_sizes = None

	# Get file-size pairs
	def group_by_size(self, items):
		self.groups = defaultdict(set)
		file_counters = []

		for item in items:
			self._file_counter = 0
			item = os.path.abspath(item)

			if os.path.isdir(item):
				if not self.allow_directory(item):
					continue

				start_time = time.perf_counter()
				print(paint(f"Started crawling 📂 {paint(item).yellow}").green, end='', flush=True)

				for root, dirs, files in os.walk(item, onerror=lambda e: logger.error(e)):
					if stop.is_set():
						print()
						logger.info("Exiting")
						sys.exit()
					dirs[:] = [_dir for _dir in dirs if self.allow_directory(os.path.join(root, _dir))]
					for file in files:
						filepath = os.path.join(root, file)
						self.file_filter(filepath, file, root)

				elapsed_time = round(time.perf_counter() - start_time, 1)
				print(paint(
						f"  {paint('➫').white}  {paint(f'{self._file_counter:,}').BLUE_white}{paint().green}"
						f" files for review found in {paint(elapsed_time).yellow} {paint().green}seconds "
				).green)
			else:
				if self.file_filter(item):
					print(paint(f"Considering file {paint(item).yellow}").green)
			file_counters.append(self._file_counter)

		self._total_files = sum(file_counters)
		return self.groups

	def allow_directory(self, dirpath):
		return not any([
			any(pattern.search(dirpath) for pattern in self.exclude_directories_patterns),
			not self.include_hidden_directories and is_hidden(dirpath)
		])

	def file_filter(self, filepath, _name=None, _dir=None):
		try:
			file = File(filepath, _name, _dir)
		except Exception as e:
			logger.error(e)
			return

		reasons_to_exclude = [
			any(pattern.search(filepath) for pattern in self.exclude_files_patterns),
			self.specific_sizes and (file.size not in self.specific_sizes),
			not self.min_size <= file.size <= self.max_size,
			os.path.islink(filepath),
			not self.include_hidden_files and file.hidden
		]

		if not any(reasons_to_exclude):
			self.groups[file.size].add(file)
			self._file_counter += 1
			return True

	def get_dupes(self):
		total_source_files = total_target_files = 0

		if not self.targets:
			files_to_read = [file for files in self.group_by_size(self.items).values() if len(files) > 1 for file in files]
			total_source_files = self._total_files
		else:
			source_files = self.specific_sizes = self.group_by_size(self.items)
			all_source_files = {file for files in source_files.values() for file in files}
			for item in self.items: # TEMP
				item = os.path.abspath(item)
				if os.path.isdir(item):
					self.exclude_directories_patterns.append(re.compile(item))
				else:
					self.exclude_files_patterns.append(re.compile(item))
			total_source_files = self._total_files

			target_files = self.group_by_size(self.targets)
			files_to_read = []
			for size, files in source_files.items():
				if size not in target_files:
					self.unmatched_files.update(files)
				else:
					files_to_read.extend(files | target_files[size])
			total_target_files = self._total_files

		bytes_to_read = sum(file.size for file in files_to_read)
		if not files_to_read:
			return [], self

		print(paint(f"Total files to consider: {paint(f'{total_source_files + total_target_files:,}').MAGENTA_white}").green)
		print()
		print(paint(f"-- Need to read {bytes_to_read:,} bytes {paint(f'({Size(bytes_to_read)})').yellow} {paint().green}from {len(files_to_read):,} files --").green)

		# Find the duplicates
		dupes = []
		start_time = time.perf_counter()

		groups, self.bytes_read = calculate_hashes(files_to_read, bytes_to_read, HASH_FUNC)

		if not self.targets:
			dupes = [Dup(*files) for files in groups.values() if len(files) > 1]
		else:
			dupes = []
			for files in groups.values():
				base_files = []
				target_files = []
				if len(files) > 1:
					for file in files:
						if file in all_source_files:
							base_files.append(file)
						else:
							target_files.append(file)

				if base_files and target_files:
					dupes.append(Dup(*target_files, basefiles=base_files))

		self.elapsed_time = round(time.perf_counter() - start_time, 1)

		# STATS 2
		self.duplicate_files = sum(dup.duplicate_files for dup in dupes)
		self.overhead_size = sum(len(dup) for dup in dupes)

		#print({file.device for dup in dupes for file in dup.files})
		return sorted(dupes, key=lambda dup: (len(dup) if not self.sort_size else dup.file_size, -dup.files[0]._mtime), reverse=True), self

stdout_handler = logging.StreamHandler()
stdout_handler.setFormatter(CustomFormatter())

logger = logging.getLogger(__name__)
logger.addHandler(stdout_handler)
logger.setLevel(logging.INFO)

def main():
	stop.clear()
	def ControlC(num, stack):
		print("\b\b", end='', flush=True)
		stop.set()
	signal.signal(signal.SIGINT, ControlC)

	parser=argparse.ArgumentParser(description="This program detects duplicate files.")

	# Main items
	parser.add_argument("ITEMS", help="Files/Directories to detect duplicates", nargs='*')
	parser.add_argument("-t", "--targets", action="append", default=[], help="Files/Directories that we want to check if the ITEMS exist in there")

	# Viewing
	parser.add_argument("-s", "--sort-size", help="Sort duplicates by size (Default: Saving size)", action="store_true")
	parser.add_argument("-u", "--show-unique", help="Show also unique files (Default: No)", action="store_true")
	parser.add_argument("-S", "--only-stats", help="Show only statistics", action="store_true")
	parser.add_argument("-I", "--non-interactive", help="Disable interactive prompts (Default: Enabled)", action="store_true")
	parser.add_argument("-V", "--verbose", help="Show files while they are being read", action="store_true")

	# Filtering
	parser.add_argument("-xf", "--exclude-files", help="Files to exclude (regex)", action="append", default=[])
	parser.add_argument("-xd", "--exclude-directories", help="Directories to exclude (regex)", action="append", default=[])
	parser.add_argument("-min", "--min-size", help="Ommit files smaller than SIZE (Bytes).", type=str, default='1', action="store")
	parser.add_argument("-max", "--max-size", help="Ommit files larger than SIZE (Bytes).", type=str, default='9Y', action="store")
	parser.add_argument("-a",  "--include-hidden", help="Include hidden files and directories (Default: No)", action="store_true")
	parser.add_argument("-hf", "--include-hidden-files", help="Include hidden files (Default: No)", action="store_true")
	parser.add_argument("-hd", "--include-hidden-directories", help="Include hidden directories (Default: No)", action="store_true")

	parser.add_argument("-v", "--version", help="Show version", action="store_true")
	args = parser.parse_args()

	# Option cooking
	if args.version:
		print(__version__)
		return

	if args.show_unique and not args.targets:
		logger.warning("The '--show-unique' option requires '--targets'")
		return

	if not sys.stdin.isatty():
		args.ITEMS.extend(sys.stdin.read().splitlines())

	if not args.ITEMS:
		args.ITEMS = ['.']

	if args.include_hidden:
		args.include_hidden_files, args.include_hidden_directories = True, True

	if args.verbose:
		global verbose
		verbose = True

	print("\n🔎 ANALYSIS\n──────────────")
	dupes, stats = DupFinder(
		args.ITEMS,
		args.targets,
		min_size=args.min_size,
		max_size=args.max_size,
		include_hidden_files=args.include_hidden_files,
		include_hidden_directories=args.include_hidden_directories,
		exclude_files=args.exclude_files,
		exclude_directories=args.exclude_directories,
		sort_size=args.sort_size
	).get_dupes()

	if not args.only_stats:
		print("\n\n✅ RESULTS\n──────────────")
		if not dupes:
			logger.info("No duplicate files!")

		for dup in dupes:
			print(dup)
		print()

	if args.show_unique:
		print(f"🚫 UNIQUE FILES ({len(stats.unmatched_files)})\n{'─' * 25}")
		for file in stats.unmatched_files:
			print(file)
		print()

	if not hasattr(stats, 'overhead_size'):
		return

	print("\n📊 STATS\n──────────────")
	print(paint(f"Total duplicate size  =>").green, paint(Size(stats.overhead_size)).red)
	print(paint(f"Duplicate files       =>").green, paint(f"{stats.duplicate_files:,}").red)
	print(paint(f"Duplicate sets        =>").green, paint(len(dupes)).yellow)
	print(paint(f"Total data read       =>").green, paint(Size(stats.bytes_read)).yellow)
	print(paint(f"Time elapsed          =>").green, paint(f"{stats.elapsed_time:,} seconds").yellow)
	print()

	if args.non_interactive:
		return

	while True:
		interactive = False
		command = ask("Action: ([I]nspect each set, [R]e-run, [V]erify all, [Ctrl-C/Q]uit): ")

		if command == "i":
			interactive = True
			break
		elif command in ("r"):
			main()
		elif command in ("v"):
			if not dupes:
				logger.warning("No duplicated to verify")
				continue
			print()
			ok = True
			for dup in dupes:
				if not dup.verify():
					ok = False
				print(dup)
				print(f"{'-' * 40}\n")

			if not ok:
				print()
				logger.critical("False positive duplicates detected")
			else:
				print(paint("All duplicates are verified!").GREEN)
			print()

		elif command in ("q", '\x03'):
			logger.info("Exiting")
			sys.exit()

	if interactive:
		for dup in dupes:
			print(dup)
			print()
			while True:
				command = ask("Action: ([R]emove, [O]pen, Open[D]irectory, [V]erify, [I]nfo, [N]ext, [Ctrl-C/Q]uit): ")
				if command == "r":
					removed = dup.remove()
					print()
					if removed:
						break
				elif command == "o":
					dup.open()
				elif command == "d":
					dup.opendir()
				elif command == "v":
					print()
					dup.verify()
					print(dup)
					print()
				elif command == "i":
					dup.info()
				elif command == "n":
					break
				elif command in ("q", "\x03"):
					logger.info("Exiting")
					sys.exit()

if __name__ == '__main__':
	main()
