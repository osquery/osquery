/**
 * \file lib/rpmhash.c
 * Hash table implemenation
 */

#include "system.h"
#include <stdio.h>
#include "debug.h"

#define Bucket JOIN(HASHTYPE,Buket)
#define Bucket_s JOIN(HASHTYPE,Buket_s)

typedef	struct  Bucket_s * Bucket;

/**
 */
struct  Bucket_s {
    Bucket next;	/*!< pointer to next item in bucket */
    HTKEYTYPE key;      /*!< hash key */
#ifdef HTDATATYPE
    int dataCount;	/*!< data entries */
    HTDATATYPE data[1];	/*!< data - grows by resizing whole bucket */
#endif
};

/**
 */
struct HASHSTRUCT {
    int numBuckets;			/*!< number of hash buckets */
    Bucket * buckets;			/*!< hash bucket array */
    hashFunctionType fn;		/*!< generate hash value for key */
    hashEqualityType eq;		/*!< compare hash keys for equality */
    hashFreeKey freeKey;
    int bucketCount;			/*!< number of used buckets */
    int keyCount;			/*!< number of keys */
#ifdef HTDATATYPE
    int dataCount;			/*!< number of data entries */
    hashFreeData freeData;
#endif
};

/**
 * Find entry in hash table.
 * @param ht            pointer to hash table
 * @param key           pointer to key value
 * @param keyHash	key hash
 * @return pointer to hash bucket of key (or NULL)
 */
static
Bucket HASHPREFIX(findEntry)(HASHTYPE ht, HTKEYTYPE key, unsigned int keyHash)
{
    unsigned int hash = keyHash % ht->numBuckets;
    Bucket b = ht->buckets[hash];

    while (b && ht->eq(b->key, key))
	b = b->next;

    return b;
}

HASHTYPE HASHPREFIX(Create)(int numBuckets,
			    hashFunctionType fn, hashEqualityType eq,
			    hashFreeKey freeKey
#ifdef HTDATATYPE
, hashFreeData freeData
#endif
)
{
    HASHTYPE ht;

    ht = xmalloc(sizeof(*ht));
    ht->numBuckets = numBuckets > 11 ? numBuckets : 11;
    ht->buckets = xcalloc(ht->numBuckets, sizeof(*ht->buckets));
    ht->freeKey = freeKey;
#ifdef HTDATATYPE
    ht->freeData = freeData;
    ht->dataCount = 0;
#endif
    ht->fn = fn;
    ht->eq = eq;
    ht->bucketCount = ht->keyCount = 0;
    return ht;
}

static void HASHPREFIX(Resize)(HASHTYPE ht, int numBuckets) {
    Bucket * buckets = xcalloc(numBuckets, sizeof(*ht->buckets));

    for (int i=0; i<ht->numBuckets; i++) {
	Bucket b = ht->buckets[i];
	Bucket nextB;
	while (b != NULL) {
	    unsigned int hash = ht->fn(b->key) % numBuckets;
	    nextB = b->next;
	    b->next = buckets[hash];
	    buckets[hash] = b;
	    b = nextB;
	}
    }
    free(ht->buckets);
    ht->buckets = buckets;
    ht->numBuckets = numBuckets;
}

unsigned int HASHPREFIX(KeyHash)(HASHTYPE ht, HTKEYTYPE key)
{
    return ht->fn(key);
}

void HASHPREFIX(AddHEntry)(HASHTYPE ht, HTKEYTYPE key, unsigned int keyHash
#ifdef HTDATATYPE
, HTDATATYPE data
#endif
)
{
    unsigned int hash = keyHash % ht->numBuckets;
    Bucket b = ht->buckets[hash];
#ifdef HTDATATYPE
    Bucket * b_addr = ht->buckets + hash;
#endif

    if (b == NULL) {
	ht->bucketCount += 1;
    }

    while (b && ht->eq(b->key, key)) {
#ifdef HTDATATYPE
	b_addr = &(b->next);
#endif
	b = b->next;
    }

    if (b == NULL) {
	ht->keyCount += 1;
	b = xmalloc(sizeof(*b));
	b->key = key;
#ifdef HTDATATYPE
	b->dataCount = 1;
	b->data[0] = data;
#endif
	b->next = ht->buckets[hash];
	ht->buckets[hash] = b;
    }
#ifdef HTDATATYPE
    else {
	if (ht->freeKey)
	    ht->freeKey(key);
	// resizing bucket TODO: increase exponentially
	// Bucket_s already contains space for one dataset
	b = *b_addr = xrealloc(
	    b, sizeof(*b) + sizeof(b->data[0]) * (b->dataCount));
	// though increasing dataCount after the resize
	b->data[b->dataCount++] = data;
    }
    ht->dataCount += 1;
#endif
    if (ht->keyCount > ht->numBuckets) {
	HASHPREFIX(Resize)(ht, ht->numBuckets * 2);
    }
}

void HASHPREFIX(AddEntry)(HASHTYPE ht, HTKEYTYPE key
#ifdef HTDATATYPE
, HTDATATYPE data
#endif
)
{
#ifdef HTDATATYPE
    HASHPREFIX(AddHEntry)(ht, key, ht->fn(key), data);
#else
    HASHPREFIX(AddHEntry)(ht, key, ht->fn(key));
#endif
}

void HASHPREFIX(Empty)( HASHTYPE ht)
{
    Bucket b, n;
    int i;

    if (ht->bucketCount == 0) return;

    for (i = 0; i < ht->numBuckets; i++) {
	b = ht->buckets[i];
	if (b == NULL)
	    continue;
	ht->buckets[i] = NULL;

	do {
	    n = b->next;
	    if (ht->freeKey)
		b->key = ht->freeKey(b->key);
#ifdef HTDATATYPE
	    if (ht->freeData) {
		int j;
		for (j=0; j < b->dataCount; j++ ) {
		    b->data[j] = ht->freeData(b->data[j]);
		}
	    }
#endif
	    b = _free(b);
	} while ((b = n) != NULL);
    }
    ht->bucketCount = 0;
    ht->keyCount = 0;
#ifdef HTDATATYPE
    ht->dataCount = 0;
#endif
}

HASHTYPE HASHPREFIX(Free)(HASHTYPE ht)
{
    if (ht==NULL)
        return ht;
    HASHPREFIX(Empty)(ht);
    ht->buckets = _free(ht->buckets);
    ht = _free(ht);

    return NULL;
}

int HASHPREFIX(HasHEntry)(HASHTYPE ht, HTKEYTYPE key, unsigned int keyHash)
{
    Bucket b;

    if (!(b = HASHPREFIX(findEntry)(ht, key, keyHash))) return 0; else return 1;
}

int HASHPREFIX(HasEntry)(HASHTYPE ht, HTKEYTYPE key)
{
    return HASHPREFIX(HasHEntry)(ht, key, ht->fn(key));
}

int HASHPREFIX(GetHEntry)(HASHTYPE ht, HTKEYTYPE key, unsigned int keyHash,
#ifdef HTDATATYPE
			 HTDATATYPE** data, int * dataCount,
#endif
			 HTKEYTYPE* tableKey)
{
    Bucket b;
    int rc = ((b = HASHPREFIX(findEntry)(ht, key, keyHash)) != NULL);

#ifdef HTDATATYPE
    if (data)
	*data = rc ? b->data : NULL;
    if (dataCount)
	*dataCount = rc ? b->dataCount : 0;
#endif
    if (tableKey && rc)
	*tableKey = b->key;

    return rc;
}

int HASHPREFIX(GetEntry)(HASHTYPE ht, HTKEYTYPE key,
#ifdef HTDATATYPE
			 HTDATATYPE** data, int * dataCount,
#endif
			 HTKEYTYPE* tableKey)
{
    return HASHPREFIX(GetHEntry)(ht, key, ht->fn(key),
#ifdef HTDATATYPE
				 data, dataCount,
#endif
				 tableKey);
}

unsigned int HASHPREFIX(NumBuckets)(HASHTYPE ht) {
    return ht->numBuckets;
}

unsigned int HASHPREFIX(UsedBuckets)(HASHTYPE ht) {
    return ht->bucketCount;
}

unsigned int HASHPREFIX(NumKeys)(HASHTYPE ht) {
    return ht->keyCount;
}

#ifdef HTDATATYPE
unsigned int HASHPREFIX(NumData)(HASHTYPE ht) {
    return ht->dataCount;
}
#endif


void HASHPREFIX(PrintStats)(HASHTYPE ht) {
    int i;
    Bucket bucket;

    int hashcnt=0, bucketcnt=0, datacnt=0;
    int maxbuckets=0;

    for (i=0; i<ht->numBuckets; i++) {
        int buckets = 0;
        for (bucket=ht->buckets[i]; bucket; bucket=bucket->next){
	    buckets++;
#ifdef HTDATATYPE
	    datacnt += bucket->dataCount;
#endif
	}
	if (maxbuckets < buckets) maxbuckets = buckets;
	if (buckets) hashcnt++;
	bucketcnt += buckets;
    }
    fprintf(stderr, "Hashsize: %i\n", ht->numBuckets);
    fprintf(stderr, "Hashbuckets: %i\n", hashcnt);
    fprintf(stderr, "Keys: %i\n", bucketcnt);
    fprintf(stderr, "Values: %i\n", datacnt);
    fprintf(stderr, "Max Keys/Bucket: %i\n", maxbuckets);
}
