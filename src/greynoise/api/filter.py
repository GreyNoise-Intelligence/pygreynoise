"""Filter module."""

import more_itertools


class Filter(object):
    """Filter lines that contain IP addresses from a given text.

    :param api: API client
    :type api: greynoise.api.GreyNoise

    """

    FILTER_TEXT_CHUNK_SIZE = 10000

    def __init__(self, api):
        self.api = api

    def filter(self, text, noise_only):
        """Filter lines that contain IP addresses from a given text.

        :param text: Text input
        :type text: file-like | str
        :param noise_only:
            If set, return only lines that contain IP addresses classified as noise,
            otherwise, return lines that contain IP addresses not classified as noise.
        :type noise_only: bool
        :return: Iterator that yields lines in chunks
        :rtype: iterable

        """
        if isinstance(text, str):
            text = text.splitlines(True)
        chunks = more_itertools.chunked(text, self.FILTER_TEXT_CHUNK_SIZE)
        for chunk in chunks:
            yield self._filter_chunk(chunk, noise_only)

    def _filter_chunk(self, text, noise_only):
        """Filter chunk of lines that contain IP addresses from a given text.

        :param text: Text input
        :type text: str
        :param noise_only:
            If set, return only lines that contain IP addresses classified as noise,
            otherwise, return lines that contain IP addresses not classified as noise.
        :type noise_only: bool
        :return: Filtered line

        """
        text_ip_addresses = set()
        for input_line in text:
            text_ip_addresses.update(self.api.IPV4_REGEX.findall(input_line))

        noise_ip_addresses = {
            result["ip"]
            for result in self.api.quick(text_ip_addresses)
            if result["noise"]
        }

        def all_ip_addresses_noisy(line):
            """Select lines that contain IP addresses and all of them are noisy.

            :param line: Line being processed.
            :type line: str
            :return: True if line contains IP addresses and all of them are noisy.
            :rtype: bool

            """
            line_ip_addresses = self.api.IPV4_REGEX.findall(line)
            return line_ip_addresses and all(
                line_ip_address in noise_ip_addresses
                for line_ip_address in line_ip_addresses
            )

        def add_markup(match):
            """Add markup to surround IP address value with proper tag.

            :param match: IP address match
            :type match: re.Match
            :return: IP address with markup
            :rtype: str

            """
            ip_address = match.group(0)
            if ip_address in noise_ip_addresses:
                tag = "noise"
            else:
                tag = "not-noise"

            return "<{tag}>{ip_address}</{tag}>".format(ip_address=ip_address, tag=tag)

        if noise_only:
            line_matches = all_ip_addresses_noisy
        else:

            def line_matches(line):
                """Match all lines that contain either text or non-noisy lines.

                :param line: Line being processed.
                :type line: str
                :return: True if line matches as expected.
                :rtype: bool

                """
                return not all_ip_addresses_noisy(line)

        filtered_lines = [
            self.api.IPV4_REGEX.subn(add_markup, input_line)[0]
            for input_line in text
            if line_matches(input_line)
        ]
        return "".join(filtered_lines)
