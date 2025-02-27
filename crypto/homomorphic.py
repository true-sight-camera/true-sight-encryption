import hashlib
from typing import Dict, Tuple, List

# Helper function to compute SHA256 hash
def compute_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

# 2D Hash function
def two_d_hash(A: List[List[int]], r: Tuple[int, int, int, int], s: str, C: Dict, M: Dict, O: Dict) -> bytes:
    if r in M:
        return M[r]
    elif r in C:
        return C[r]
    elif len(r) == 2:  # Single pixel case
        a, c = r
        return compute_hash(b"0" + bytes([A[a][c]]))
    else:
        t = b""
        x = s
        for i in range(4):  # Top, Right, Bottom, Left
            rx = calculate_child_region(r, x)
            if rx:
                t += two_d_hash(A, rx, x, C, M, O)
            x = next_direction(x)
        h = compute_hash(b"1" + t)

        if r not in C:
            C[r] = h
        else:
            del C[r]

        if r in O:
            O[r] = h

        return h

# Function to calculate child region based on direction
def calculate_child_region(r: Tuple[int, int, int, int], direction: str) -> Tuple[int, int, int, int]:
    top, bottom, left, right = r
    mid_vertical = (top + bottom) // 2
    mid_horizontal = (left + right) // 2

    if direction == "T":
        return (top, mid_vertical, left, right)
    elif direction == "R":
        return (top, bottom, mid_horizontal + 1, right)
    elif direction == "B":
        return (mid_vertical + 1, bottom, left, right)
    elif direction == "L":
        return (top, bottom, left, mid_horizontal)
    else:
        return None

# Clockwise direction helper
def next_direction(current: str) -> str:
    directions = ["T", "R", "B", "L"]
    index = directions.index(current)
    return directions[(index + 1) % 4]

# Witness set function
def witness_set(R: Tuple[int, int, int, int], r_hat: Tuple[int, int, int, int], w_hat: List, r_prime: Tuple[int, int, int, int]) -> List:
    if not r_prime:
        return [R]
    if r_prime == R:
        return []

    children = get_children(R)
    if r_prime_spans(R, r_prime):
        c1, c2 = select_children_spanning(R, r_prime)
    else:
        c1, c2 = select_complement_children(R, w_hat)

    return (
        children.difference({c1, c2})
        .union(
            witness_set(c1, intersect(c1, r_hat), w_hat, intersect(c1, r_prime))
        )
        .union(
            witness_set(c2, intersect(c2, r_hat), w_hat, intersect(c2, r_prime))
        )
    )

# Helpers for witness-set logic
def r_prime_spans(R: Tuple[int, int, int, int], r_prime: Tuple[int, int, int, int]) -> bool:
    # Example check for spanning
    return R[0] <= r_prime[0] and R[1] >= r_prime[1] and R[2] <= r_prime[2] and R[3] >= r_prime[3]

def get_children(R: Tuple[int, int, int, int]) -> List[Tuple[int, int, int, int]]:
    # Calculate and return children regions based on R
    return [
        calculate_child_region(R, "T"),
        calculate_child_region(R, "R"),
        calculate_child_region(R, "B"),
        calculate_child_region(R, "L"),
    ]

def select_children_spanning(R: Tuple[int, int, int, int], r_prime: Tuple[int, int, int, int]) -> Tuple:
    # Select children that span R in the same direction as r_prime
    children = get_children(R)
    return children[:2]  # Simplified; replace with actual logic

def select_complement_children(R: Tuple[int, int, int, int], w_hat: List) -> Tuple:
    # Select complement children not in w_hat
    children = get_children(R)
    return tuple(c for c in children if c not in w_hat)

def intersect(region1: Tuple[int, int, int, int], region2: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    # Return intersection of two regions
    return (
        max(region1[0], region2[0]),
        min(region1[1], region2[1]),
        max(region1[2], region2[2]),
        min(region1[3], region2[3]),
    )

# Example usage to sign an image
def sign_image(image: List[List[int]], private_key):
    # Divide the image into a 2D array of pixels (A)
    A = image

    # Define the full region of the image (r) as (top, bottom, left, right)
    r = (0, len(A) - 1, 0, len(A[0]) - 1)

    # Initialize caches and metadata
    C, M, O = {}, {}, {}

    # Compute the hash of the entire image using 2D hash
    image_hash = two_d_hash(A, r, "T", C, M, O)

    # Sign the hash with the private key
    signed_hash = private_key.sign(image_hash)

    return signed_hash, image_hash
