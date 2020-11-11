#include <algorithm>
#include <random>

template <class RandomIt>
void random_shuffle(RandomIt first, RandomIt last) {
  std::random_device rng;
  std::mt19937 urng(rng());
  std::shuffle(first, last, urng);
}
