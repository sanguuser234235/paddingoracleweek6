= Padding Oracle Attack Lab - Answers and Reflections

== Task 1: Understand the Components

1.  *Analyze the `padding_oracle` function. How does it determine if padding is valid?*

    The `padding_oracle` function works by first trying to decrypt the provided ciphertext using the secret AES key and the provided IV in CBC mode. After decryption, it attempts to remove the padding using the standard PKCS#7 unpadding mechanism provided by the `cryptography` library. The core of the validation happens when the `unpadder.finalize()` method is called. If the decrypted data ends with a valid PKCS#7 padding sequence (e.g., `\x03\x03\x03` or `\x05\x05\x05\x05\x05`), this method succeeds. However, if the final bytes do not form a valid padding sequence according to the PKCS#7 standard, the `finalize()` method raises a `ValueError`. The function catches this specific error (along with `TypeError`) and returns `false` in that case. If no error is caught during the unpadding process, it means the padding was valid, and the function returns `true`. It also performs initial checks to ensure the ciphertext length is a non-zero multiple of the block size.

2.  *What is the purpose of the IV in CBC mode?*

    The Initialization Vector (IV) in CBC mode is primarily used to introduce randomness and ensure that encrypting the same plaintext multiple times with the same key will produce different ciphertexts. For the very first block of plaintext, the IV is XORed with the plaintext *before* it gets encrypted. For all subsequent blocks, the *previous ciphertext block* is used for this XOR operation instead of the IV. This chaining mechanism means each ciphertext block depends on all preceding plaintext blocks. The IV essentially kickstarts this process, ensuring the first block's encryption is unique even if the plaintext starts the same way as another message. During decryption, the IV is needed to correctly decrypt the first block of ciphertext (by XORing it with the result of the AES decryption of the first block).

3.  *Why does the ciphertext need to be a multiple of the block size?*

    AES, like most block ciphers, operates on fixed-size blocks of data (16 bytes in this case). CBC mode processes the data one block at a time. To ensure the final block of plaintext is always full before encryption, padding schemes like PKCS#7 are used. This padding adds specific bytes to the end of the message so that its total length becomes an exact multiple of the block size. Since the encryption process works block-by-block on this padded data, the resulting ciphertext (excluding the IV, which is one block itself) will also naturally be a multiple of the block size. Therefore, the total data transmitted (IV + ciphertext blocks) must consist of a whole number of blocks for the decryption and unpadding process to function correctly according to the CBC and PKCS#7 standards. The oracle function specifically checks this requirement.

#pagebreak()
4.  *Draw out the XOR operations involved in CBC decryption*

#image("./CBC_decryption.svg.png")

I got this image from wikipedia.

== Reflections on the Lab

To get a better handle on the `padding oracle attack`, especially the step-by-step process of manipulating the ciphertext bytes and understanding the XOR logic, I found a few online resources really helpful alongside the course material. Specifically, these videos helped visualize the attack:

- #link("https://www.youtube.com/watch?v=O5SeQxErXA4")
- #link("https://www.youtube.com/watch?v=6yHM19rQjDo")
- #link("https://www.youtube.com/watch?v=uDHo-UAM6_4")

Working through this lab and watching these explanations was quite eye-opening. It really highlighted how seemingly small details in the implementation of cryptographic protocols can lead to significant vulnerabilities. The fact that just revealing whether padding is valid or not is enough to completely decrypt the message shows how careful developers need to be. Some of the videos, along with the course material, were especially illuminating in showing how subtle mistakes, like incorrect handling of `padding` or even potentially differences in processing time (`timing attacks`, though not directly implemented here), can entirely break the security of an encryption scheme. It emphasizes that just using a strong algorithm like `AES` isn't enough; it has to be implemented correctly within a secure protocol.


