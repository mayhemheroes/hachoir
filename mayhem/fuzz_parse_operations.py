#! /usr/bin/env python3
import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports(include=["hachoir"]):
    import hachoir.parser
    import hachoir.metadata

# Exceptions
from hachoir.stream.input import StreamError
# Quiet the library's logging
from hachoir.core import config
config.quiet = True

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeMemoryFile(all_data=True) as fp, hachoir.parser.createParser(fp) as parser:
            if parser:
                hachoir.metadata.extractMetadata(parser)
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
