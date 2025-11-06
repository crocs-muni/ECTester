from dataclasses import dataclass
import hashlib


def hash_divisors(divisors: set[int]) -> bytes:
    return hashlib.blake2b(str(sorted(divisors)).encode(), digest_size=8).digest()


@dataclass
class ProbMap:
    """
    A ProbMap is a mapping from integers (base point order q) to floats (error probability for some scalar
    multiplication implementation, i.e. Config). The probability map is constructed for a given set of
    `divisors` (the base point orders q). Probability maps can be narrowed or merged. A narrowing restricts
    the probability map to a smaller set of `divisors`. A merging takes another probability map using the
    same divisor set and updates the probabilities to a weighted average of the two probability maps
    (the weight is the number of samples).
    """

    probs: dict[int, float]
    divisors_hash: bytes
    samples: int

    def __len__(self):
        return len(self.probs)

    def __iter__(self):
        yield from self.probs

    def __getitem__(self, i):
        return self.probs[i] if i in self.probs else 0.0

    def __contains__(self, item):
        return item in self.probs

    def __eq__(self, other):
        if not isinstance(other, ProbMap):
            return False
        return self.divisors_hash == other.divisors_hash and self.probs == other.probs

    def id(self):
        return hash((frozenset(self.probs.items()), self.divisors_hash))

    def keys(self):
        return self.probs.keys()

    def values(self):
        return self.probs.values()

    def items(self):
        return self.probs.items()

    def narrow(self, divisors: set[int]):
        """Narrow the probability map to the new set of divisors (must be a subset of the current set)."""
        divisors_hash = hash_divisors(divisors)
        if self.divisors_hash == divisors_hash:
            # Already narrow.
            return
        for kdel in set(self.probs.keys()).difference(divisors):
            del self.probs[kdel]
        self.divisors_hash = divisors_hash

    def merge(self, other: "ProbMap") -> None:
        """Merge the `other` probability map into this one (must share the divisor set)."""
        if self.divisors_hash != other.divisors_hash:
            raise ValueError(
                "Merging can only work on probmaps created for same divisors."
            )
        new_keys = set(self.keys()).union(other.keys())
        result = {}
        for key in new_keys:
            sk = self[key]
            ok = other[key]
            result[key] = (sk * self.samples + ok * other.samples) / (
                self.samples + other.samples
            )
        self.probs = result
        self.samples += other.samples
