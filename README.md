# RustyEDES (Enhanced Data Encryption Standard)

## Summary
E-DES is a variant of DES that attempts to fix the main DES shortfalls, which are the key size and openness to potential attacks using knowledge about its S-Boxes.
in E-DES, keys are always 256 bits long and the S-Boxes are generated dynamically (16 boxes, instead of 8), from the keys.

Having Key-Dependent S-Boxes means we can significantly reduce the amount of processing needed to encrypt and decrypt messages, compared to DES. Essentially, provided we already have the S-Boxes generated and a set of 16 keys (derived from a main one), all we need is to use a Feistel Network approach, as explained [here](https://en.wikipedia.org/wiki/Feistel_cipher).

![image](https://user-images.githubusercontent.com/16304428/202696534-1c821202-3754-430b-ac95-f73d9b702d9e.png)

The process looks like the above image, stolen from the wikipedia page.

## Benchmarks
Using Criterion's library, the results show that E-DES is pretty fast. In this benchmark, I'm also comparing against a C implementation, which you can find at [https://github.com/rezzmk/E-DES](https://github.com/rezzmk/E-DES). Results show that C is actually the fastest (with E-DES), although I'm sure Rust can beat it, with some optimization work, reducing memory allocations mainly.

![image](https://user-images.githubusercontent.com/16304428/202698736-0fa31738-3e71-4e9c-8273-1dc71d3c12aa.png)

> Note: This is mostly academic work, I'm by no means remotely close to an expert in cryptography. It's just a stepping stone in my learning proggress.
