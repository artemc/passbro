import unittest

from passbro.mask import MIN_SECRET_LENGTH, mask


class MaskTests(unittest.TestCase):
    def test_masks_multiple_occurrences(self):
        data = b"token=long-secret; retry with long-secret"

        self.assertEqual(
            mask(data, ["long-secret"]),
            "token=[hidden]; retry with [hidden]".encode("utf-8"),
        )

    def test_masks_nested_value(self):
        data = b"prefix-abcd-efgh-suffix and abcd"

        self.assertEqual(
            mask(data, ["abcd", "abcd-efgh"]),
            b"prefix-"
            + "[hidden]".encode("utf-8")
            + b"-suffix and "
            + "[hidden]".encode("utf-8"),
        )

    def test_masks_overlapping_secrets_with_one_marker(self):
        self.assertEqual(
            mask(b"xabcdef", ["abcdef", "xabc"]),
            "[hidden]".encode("utf-8"),
        )

    def test_masks_partially_overlapping_secrets_with_one_marker(self):
        self.assertEqual(
            mask(b"abcdefgh", ["abcdef", "defgh"]),
            "[hidden]".encode("utf-8"),
        )

    def test_masks_overlapping_occurrences_of_one_secret(self):
        self.assertEqual(
            mask(b"ababab", ["abab"]),
            "[hidden]".encode("utf-8"),
        )

    def test_does_not_rescan_mask_marker(self):
        data = "long-secret and hidden".encode("utf-8")

        self.assertEqual(
            mask(data, ["long-secret", "hidden"]),
            "[hidden] and [hidden]".encode("utf-8"),
        )

    def test_masks_cyrillic_secret_by_utf8_bytes(self):
        data = "ответ: пароль открыт".encode("utf-8")

        self.assertEqual(
            mask(data, ["пароль"]),
            "ответ: [hidden] открыт".encode("utf-8"),
        )

    def test_ignores_secrets_shorter_than_four_characters(self):
        data = b"abc remains visible"

        self.assertEqual(mask(data, ["abc"]), data)

    def test_secret_length_threshold_is_public(self):
        self.assertEqual(MIN_SECRET_LENGTH, 4)

    def test_cyrillic_secret_threshold_counts_characters_not_bytes(self):
        secret = "ёж"
        data = f"значение: {secret}".encode("utf-8")

        self.assertEqual(len(secret.encode("utf-8")), 4)
        self.assertEqual(mask(data, [secret]), data)

    def test_empty_secret_list_leaves_data_unchanged(self):
        data = b"some output"

        self.assertEqual(mask(data, []), data)


if __name__ == "__main__":
    unittest.main()
