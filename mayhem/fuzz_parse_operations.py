#! /usr/bin/env python3

import atheris
import sys
import io
import fuzz_helpers
from contextlib import contextmanager
with atheris.instrument_imports():
    from hachoir.metadata.metadata import extractMetadata

import hachoir.parser
# Exceptions
from hachoir.stream.input import StreamError

# Quiet the library's logging
from hachoir.core import config
config.quiet = True

@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeMemoryFile(all_data=True) as fp, nostdout(), hachoir.parser.createParser(fp) as parser:
            if parser:
                extractMetadata(parser)
    except StreamError:
        return -1
    except AttributeError as e:
        if '__enter__' in str(e):
            return -1
        raise

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
