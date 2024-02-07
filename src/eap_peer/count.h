#ifndef COUNT_H
#define COUNT_H

struct cnt {
    int count;
};

void cnt_set_overflow(struct cnt cnt, int overflow)
{
    cnt.count = 0x00ffff00 & (overflow << 8);
}

void cnt_set_sqn(struct cnt cnt, int sqn)
{
    cnt.count = 0x000000ff & sqn;
}

void cnt_set(struct cnt cnt, int overflow, int sqn) 
{
    cnt_set_overflow(cnt, overflow);
    cnt_set_sqn(cnt, sqn);
}

void cnt_add(struct cnt cnt)
{
    cnt.count = (++cnt.count) & 0x00ffffff;
}

int cnt_sqn(struct cnt cnt)
{
    return cnt.count & 0x000000ff;
}

int cnt_overflow(struct cnt cnt)
{
    return (cnt.count & 0x00ffff00) >> 8;
}

#endif