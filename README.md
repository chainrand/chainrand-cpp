# Chainrand-cpp — Verifiable hybrid-chain RNG.

Many applications require off-chain generation of random numbers for efficiency, security, etc.

This class allows you to generate a stream of deterministic, high-quality,  
cryptographically secure random numbers.

By seeding it with a Chainlink VRF result that is requested **only once for the project**,  
it can be used to demonstrate that the random numbers are **not cherry-picked**.

# Requirements

C++98 and above compiler. 

# Installation

Just copy and paste and include `include/chainrand.h` into your project.

## Usage

```c++
chainrand::CRNG crng("base10(<RNG_VRF_RESULT>)" "<RNG_SEED_KEY>");
// prints 10 determinstic random numbers between [0, 1)
for (int i = 0; i < 10; ++i) {
    std::cout << crng() << "\n";
}
```

Compile with optimizations `-march=native` flag to enable usage of AES instructions. 

# Reproducibility

Current and future versions of this library will generate the same stream of random numbers from the same seed.

# Functions

## (constructor)

```c++
template <class Str> CRNG(Str seed);
```

Creates an instance of the crng initialized with the `seed`.

**Parameters:**

- `seed` If empty, defaults to the empty string `""`.

**Example:**

```c++
chainrand::CRNG crng("base10(<RNG_VRF_RESULT>)" + "<RNG_SEED_KEY>");
```

## nextUint

```c++
template <class T> T nextUint();
uint8_t nextUint8();
uint16_t nextUint16();
uint32_t nextUint32();
uint64_t nextUint64();
```

**Returns:**
Returns a single uniform random number within [0, (1<<(sizeof(T)*8))-1].

## nextDouble / random / operator()

```c++
double nextDouble();
double operator() ();
double random();
```

Returns a single uniform random number within [0,1).
The numbers are in multiples of 2**-53.

**Parameters:**
none

**Returns:**
Returns a single uniform random number within [0,1).


## nextFloat

```c++
float nextFloat();
```

Returns a single uniform random number within [0,1).
The numbers are in multiples of 2**-24.

**Parameters:**
none

**Returns:**
Returns a single uniform random number within [0,1).

## randrange

```c++
int64_t randrange(int64_t start, int64_t stop, int64_t step);
int64_t randrange(int64_t start, int64_t stop);
int64_t randrange(int64_t stop);
```

Returns a random integer uniformly distributed in [start, stop).  
The integers are spaced with intervals of |step|.

**Parameters:**

- `start` The start of the range. (optional, default=`0`)
- `stop` The end of the range.
- `step` The interval step. (optional, default=`1`)

**Returns:**

A random integer uniformly distributed in [start, stop).

**Examples:**

```c++
int64_t r;
r = crng.randrange(3); // returns a random number in {0,1,2}
r = crng.randrange(-3); // returns a random number in {0,-1,-2}
r = crng.randrange(0, 6, 2); // returns a random number in {0,2,4}
r = crng.randrange(5, 0, 1); // returns a random number in {5,4,3,2,1}
r = crng.randrange(5, -5, -2); // returns a random number in {5,3,1,-1,-3}
```

## randint

```c++
int64_t randint(int64_t start, int64_t stop);
int64_t randint(int64_t stop);
```

Returns a random integer uniformly distributed in [start, stop].  
The integers are spaced with intervals of |step|.

**Parameters:**

- `start` The start of the range. (optional, default=`0`)
- `stop` The end of the range.

**Returns:**

A random integer uniformly distributed in [start, stop].

**Examples:**

```c++
int64_t r;
r = crng.randint(3); // returns a random number in {0,1,2,3}
r = crng.randint(-3); // returns a random number in {0,-1,-2,-3}
r = crng.randint(-3, 1); // returns a random number in {-3,-2,-1,0,1}
r = crng.randint(3, -1); // returns a random number in {3,2,1,0,-1}
```

## choose (iterator)

```c++
template <class ChoicePointer, class PopulationIterator, class WeightsIterator>
bool choose(ChoicePointer choicePointer,
            PopulationIterator populationBegin,
            PopulationIterator populationEnd,
            WeightsIterator weightsBegin,
            WeightsIterator weightsEnd);
```

Chooses a random element from the population.

`ChoicePointer`, `PopulationIterator`, `WeightsIterator`  
can be plain old pointer types, or pointer-like classes. 

If weights is not provided, every element of population will be equally weighted.

If weights are provided,  
the first `min(populationEnd - populationBegin, weightsEnd - weightsBegin)`  
elements of the population will be considered.

If the sum of the weights is less than or equal to zero,  
every element of population will be equally weighted.

**Parameters:**

- `choicePointer[out]`  A pointer to the choosen element.
- `populationBegin` An iterator to the start of the population.
- `populationEnd` An iterator to the end of the population.
- `weightsBegin` An iterator to the start of the population. (optional)
- `weightsEnd` An iterator to the end of the population. (optional)

**Returns:**

Whether an element has been choosen. 

**Examples:**

```c++
std::vector<int> population;
population.push_back(1);
population.push_back(2);
population.push_back(3);
int choice;
if (crng.choose(choice, population.begin(), population.end())) {
    std::cout << choice << "\n";
}

std::vector<double> weights;
weights.push_back(10);
weights.push_back(1);
weights.push_back(0.1);
if (crng.choose(choice, population.begin(), population.end(), 
                weights.begin(), weights.end())) {
    std::cout << choice << "\n";
}
```

## choose (vector)

```c++
template <class ChoicePointer, class Population, class Weights>
bool choose(ChoicePointer choicePointer,
            const Population &population,
            const Weights &weights);
```

Chooses a random element from the population.

`Population`, `Weight` can be `std::vector`,   
or classes with the `operator[]` and `size()` methods.

If weights is not provided, every element of population will be equally weighted.

If weights are provided,  
the first `min(population.size(), weights.size())`  
elements of the population will be considered.

If the sum of the weights is less than or equal to zero,  
every element of population will be equally weighted.

**Parameters:**

- `choicePointer[out]`  A pointer to the choosen element.
- `population` A vector/array-like container of elements.
- `weights` A vector/array-like container of weights. (optional)

**Returns:**

Whether an element has been choosen. 

**Examples:**

```c++
std::vector<int> population;
population.push_back(1);
population.push_back(2);
population.push_back(3);
int choice;
if (crng.choose(choice, population)) {
    std::cout << choice << "\n";
}

std::vector<double> weights;
weights.push_back(10);
weights.push_back(1);
weights.push_back(0.1);
if (crng.choose(choice, population, weights)) {
    std::cout << choice << "\n";
}
```

## sample (iterator)

```c++
template <class CollectedIterator, class PopulationIterator, class WeightsIterator>
size_t sample(CollectedIterator collectedBegin,
              PopulationIterator populationBegin,
              PopulationIterator populationEnd,
              size_t k,
              WeightsIterator weightsBegin,
              WeightsIterator weightsEnd);
```

Chooses `k` random elements from the population **without** replacement.

`CollectedIterator`, `PopulationIterator`, `WeightsIterator`  
can be plain old pointer types, or pointer-like classes. 

If `k` is more than the length of the population, only `k` elements will be returned.

If weights is not provided, every element of population will be equally weighted.

If weights are provided,  
the first `min(populationEnd - populationBegin, weightsEnd - weightsBegin)`  
elements of the population will be considered.

If the sum of the weights is less than or equal to zero,  
every element of population will be equally weighted.

**Parameters:**

- `collectedBegin[out]` An iterator to the collected results.
- `populationBegin` An iterator to the start of the population.
- `populationEnd` An iterator to the end of the population.
- `k` The number of elements to choose. (optional, default=`1`)
- `weightsBegin` An iterator to the start of the weights. (optional)
- `weightsEnd` An iterator to the end of the weights. (optional)

**Returns:**

The number of elements choosen.

**Examples:**

```c++
const int k = 2;
std::vector<int> population, collected(k);
population.push_back(1);
population.push_back(2);
population.push_back(3);

crng.sample(collected.begin(), population.begin(), population.end(), k);

for (int i = 0; i < k; ++i)
    std::cout << collected[i] << " ";
std::cout << "\n";

std::vector<double> weights;
weights.push_back(10);
weights.push_back(1);
weights.push_back(0.1);
crng.sample(collected.begin(), population.begin(), population.end(), k, 
            weights.begin(), weights.end());

for (int i = 0; i < k; ++i)
    std::cout << collected[i] << " ";
std::cout << "\n";
```

## sample (vector)

```c++
template <class Collected, class Population, class Weights>
size_t sample(Collected &collected,
        const Population &population,
        size_t k,
        const Weights &weights);
```

Chooses `k` random elements from the population **without** replacement.

The `Population` and `Weights` can be `std::vector`,   
or classes with the `operator[]` and `size()` methods.

If `k` is more than the length of the population, only `k` elements will be returned.

If weights is not provided, every element of population will be equally weighted.

If weights are provided,  
the first `min(populationEnd - populationBegin, weightsEnd - weightsBegin)`  
elements of the population will be considered.

If the sum of the weights is less than or equal to zero,  
every element of population will be equally weighted.

**Parameters:**

- `collected[out]` A vector/array-like container of elements.
- `population` A vector/array-like container of elements.
- `k` The number of elements to choose. (optional, default=`1`)
- `weights` A vector/array-like container of weights. (optional)

**Returns:**

The number of elements choosen.

**Examples:**

```c++
const int k = 2;
std::vector<int> population, collected(k);
population.push_back(1);
population.push_back(2);
population.push_back(3);

crng.sample(collected.begin(), population.begin(), population.end(), k);

for (int i = 0; i < k; ++i)
    std::cout << collected[i] << " ";
std::cout << "\n";

std::vector<double> weights;
weights.push_back(10);
weights.push_back(1);
weights.push_back(0.1);
crng.sample(collected.begin(), population.begin(), population.end(), k, 
            weights.begin(), weights.end());

for (int i = 0; i < k; ++i)
    std::cout << collected[i] << " ";
std::cout << "\n";
```


## shuffle (iterator)

```c++
template <class RandomAccessIterator>
void shuffle(RandomAccessIterator begin, RandomAccessIterator end);
```

Shuffles the elements in-place.

`RandomAccessIterator` can be plain old pointer type, or pointer-like class. 

**Parameters:**

- `begin[in/out]` An iterator to the start of the sequence.
- `end[in/out]` An iterator to the end of the sequence.


## shuffle (vector)

```c++
template <class Vector> 
void shuffle(Vector &v);
```

Shuffles the elements in-place.

`Vector` can be `std::vector`,  
or class with the `operator[]` and `size()` methods.

**Parameters:**

- `v[in/out]` A vector/array-like container of elements.


## gauss

```c++
double gauss(double mu, double sigma);
```

Normal distribution, also called the Gaussian distribution. 

**Parameters:**

- `mu`  The mean. (optional, default=`0.0`)
- `sigma` The standard deviation. (optional, default=`1.0`)

**Returns:**

A random number from the Gaussian distribution.

# License

MIT
