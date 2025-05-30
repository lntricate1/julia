# This file is a part of Julia. License is MIT: https://julialang.org/license

## generic operations on numbers ##

# Numbers are convertible
convert(::Type{T}, x::T)      where {T<:Number} = x
convert(::Type{T}, x::Number) where {T<:Number} = T(x)::T

"""
    isinteger(x)::Bool

Test whether `x` is numerically equal to some integer.

# Examples
```jldoctest
julia> isinteger(4.0)
true
```
"""
isinteger(x::Integer) = true

"""
    iszero(x)

Return `true` if `x == zero(x)`; if `x` is an array, this checks whether
all of the elements of `x` are zero.

See also: [`isone`](@ref), [`isinteger`](@ref), [`isfinite`](@ref), [`isnan`](@ref).

# Examples
```jldoctest
julia> iszero(0.0)
true

julia> iszero([1, 9, 0])
false

julia> iszero([false, 0, 0])
true
```
"""
iszero(x) = x == zero(x) # fallback method

"""
    isone(x)

Return `true` if `x == one(x)`; if `x` is an array, this checks whether
`x` is an identity matrix.

# Examples
```jldoctest
julia> isone(1.0)
true

julia> isone([1 0; 0 2])
false

julia> isone([1 0; 0 true])
true
```
"""
isone(x) = x == one(x) # fallback method

"""
    isfinite(f)::Bool

Test whether a number is finite.

# Examples
```jldoctest
julia> isfinite(5)
true

julia> isfinite(NaN32)
false
```
"""
isfinite(x::Number) = iszero(x - x)

size(x::Number) = ()
size(x::Number, d::Integer) = d < 1 ? throw(BoundsError()) : 1
axes(x::Number) = ()
axes(x::Number, d::Integer) = d < 1 ? throw(BoundsError()) : OneTo(1)
eltype(::Type{T}) where {T<:Number} = T
ndims(x::Number) = 0
ndims(::Type{<:Number}) = 0
length(x::Number) = 1
firstindex(x::Number) = 1
firstindex(x::Number, d::Int) = d < 1 ? throw(BoundsError()) : 1
lastindex(x::Number) = 1
lastindex(x::Number, d::Int) = d < 1 ? throw(BoundsError()) : 1
IteratorSize(::Type{<:Number}) = HasShape{0}()
keys(::Number) = OneTo(1)

getindex(x::Number) = x
function getindex(x::Number, i::Integer)
    @inline
    @boundscheck i == 1 || throw(BoundsError(x, i))
    x
end
function getindex(x::Number, I::Integer...)
    @inline
    @boundscheck all(isone, I) || throw(BoundsError(x, I))
    x
end
get(x::Number, i::Integer, default) = isone(i) ? x : default
get(x::Number, ind::Tuple, default) = all(isone, ind) ? x : default
get(f::Callable, x::Number, i::Integer) = isone(i) ? x : f()
get(f::Callable, x::Number, ind::Tuple) = all(isone, ind) ? x : f()

first(x::Number) = x
last(x::Number) = x
copy(x::Number) = x # some code treats numbers as collection-like

"""
    signbit(x)

Return `true` if the value of the sign of `x` is negative, otherwise `false`.

See also [`sign`](@ref) and [`copysign`](@ref).

# Examples
```jldoctest
julia> signbit(-4)
true

julia> signbit(5)
false

julia> signbit(5.5)
false

julia> signbit(-4.1)
true
```
"""
signbit(x::Real) = x < 0

"""
    ispositive(x)

Test whether `x > 0`. See also [`isnegative`](@ref).

!!! compat "Julia 1.13"
    This function requires at least Julia 1.13.

# Examples
```jldoctest
julia> ispositive(-4.0)
false

julia> ispositive(99)
true

julia> ispositive(0.0)
false
```
"""
ispositive(x::Real) = x > 0

"""
    isnegative(x)

Test whether `x < 0`. See also [`ispositive`](@ref).

!!! compat "Julia 1.13"
    This function requires at least Julia 1.13.

# Examples
```jldoctest
julia> isnegative(-4.0)
true

julia> isnegative(99)
false

julia> isnegative(-0.0)
false
```
"""
isnegative(x::Real) = x < 0

"""
    sign(x)

Return zero if `x==0` and ``x/|x|`` otherwise (i.e., ±1 for real `x`).

See also [`signbit`](@ref), [`zero`](@ref), [`copysign`](@ref), [`flipsign`](@ref).

# Examples
```jldoctest
julia> sign(-4.0)
-1.0

julia> sign(99)
1

julia> sign(-0.0)
-0.0

julia> sign(0 + im)
0.0 + 1.0im
```
"""
sign(x::Number) = iszero(x) ? x/abs(oneunit(x)) : x/abs(x)
sign(x::Real) = ifelse(x < zero(x), oftype(one(x),-1), ifelse(x > zero(x), one(x), typeof(one(x))(x)))
sign(x::Unsigned) = ifelse(x > zero(x), one(x), oftype(one(x),0))
abs(x::Real) = ifelse(signbit(x), -x, x)

"""
    abs2(x)

Squared absolute value of `x`.

This can be faster than `abs(x)^2`, especially for complex
numbers where `abs(x)` requires a square root via [`hypot`](@ref).

See also [`abs`](@ref), [`conj`](@ref), [`real`](@ref).

# Examples
```jldoctest
julia> abs2(-3)
9

julia> abs2(3.0 + 4.0im)
25.0

julia> sum(abs2, [1+2im, 3+4im])  # LinearAlgebra.norm(x)^2
30
```
"""
abs2(x::Number) = abs(x)^2
abs2(x::Real) = x*x

"""
    flipsign(x, y)

Return `x` with its sign flipped if `y` is negative. For example `abs(x) = flipsign(x,x)`.

# Examples
```jldoctest
julia> flipsign(5, 3)
5

julia> flipsign(5, -3)
-5
```
"""
flipsign(x::Real, y::Real) = ifelse(signbit(y), -x, +x) # the + is for type-stability on Bool

"""
    copysign(x, y) -> z

Return `z` which has the magnitude of `x` and the same sign as `y`.

# Examples
```jldoctest
julia> copysign(1, -2)
-1

julia> copysign(-1, 2)
1
```
"""
copysign(x::Real, y::Real) = ifelse(signbit(x)!=signbit(y), -x, +x)

conj(x::Real) = x
transpose(x::Number) = x
adjoint(x::Number) = conj(x)
angle(z::Real) = atan(zero(z), z)

"""
    inv(x)

Return the multiplicative inverse of `x`, such that `x*inv(x)` or `inv(x)*x`
yields [`one(x)`](@ref) (the multiplicative identity) up to roundoff errors.

If `x` is a number, this is essentially the same as `one(x)/x`, but for
some types `inv(x)` may be slightly more efficient.

# Examples
```jldoctest
julia> inv(2)
0.5

julia> inv(1 + 2im)
0.2 - 0.4im

julia> inv(1 + 2im) * (1 + 2im)
1.0 + 0.0im

julia> inv(2//3)
3//2
```

!!! compat "Julia 1.2"
    `inv(::Missing)` requires at least Julia 1.2.
"""
inv(x::Number) = one(x)/x


"""
    widemul(x, y)

Multiply `x` and `y`, giving the result as a larger type.

See also [`promote`](@ref), [`Base.add_sum`](@ref).

# Examples
```jldoctest
julia> widemul(Float32(3.0), 4.0) isa BigFloat
true

julia> typemax(Int8) * typemax(Int8)
1

julia> widemul(typemax(Int8), typemax(Int8))  # == 127^2
16129
```
"""
widemul(x::Number, y::Number) = widen(x)*widen(y)

iterate(x::Number) = (x, nothing)
iterate(x::Number, ::Any) = nothing
isempty(x::Number) = false
in(x::Number, y::Number) = x == y

map(f, x::Number, ys::Number...) = f(x, ys...)

"""
    zero(x)
    zero(::Type)

Get the additive identity element for `x`. If the additive identity can be deduced
from the type alone, then a type may be given as an argument to `zero`.

For example, `zero(Int)` will work because the additive identity is the same for all
instances of `Int`, but `zero(Vector{Int})` is not defined because vectors of different
lengths have different additive identities.

See also [`iszero`](@ref), [`one`](@ref), [`oneunit`](@ref), [`oftype`](@ref).

# Examples
```jldoctest
julia> zero(1)
0

julia> zero(big"2.0")
0.0

julia> zero(rand(2,2))
2×2 Matrix{Float64}:
 0.0  0.0
 0.0  0.0
```
"""
zero(x::Number) = oftype(x,0)
zero(::Type{T}) where {T<:Number} = convert(T,0)
zero(::Type{Union{}}, slurp...) = Union{}(0)

"""
    one(x)
    one(T::Type)

Return a multiplicative identity for `x`: a value such that
`one(x)*x == x*one(x) == x`. If the multiplicative identity can
be deduced from the type alone, then a type may be given as
an argument to `one` (e.g. `one(Int)` will work because the
multiplicative identity is the same for all instances of `Int`,
but `one(Matrix{Int})` is not defined because matrices of
different shapes have different multiplicative identities.)

If possible, `one(x)` returns a value of the same type as `x`,
and `one(T)` returns a value of type `T`.  However, this may
not be the case for types representing dimensionful quantities
(e.g. time in days), since the multiplicative
identity must be dimensionless.  In that case, `one(x)`
should return an identity value of the same precision
(and shape, for matrices) as `x`.

If you want a quantity that is of the same type as `x`, or of type `T`,
even if `x` is dimensionful, use [`oneunit`](@ref) instead.

See also the [`identity`](@ref) function,
and `I` in [`LinearAlgebra`](@ref man-linalg) for the identity matrix.

# Examples
```jldoctest
julia> one(3.7)
1.0

julia> one(Int)
1

julia> import Dates; one(Dates.Day(1))
1
```
"""
one(::Type{T}) where {T<:Number} = convert(T,1)
one(x::T) where {T<:Number} = one(T)
one(::Type{Union{}}, slurp...) = Union{}(1)
# note that convert(T, 1) should throw an error if T is dimensionful,
# so this fallback definition should be okay.

"""
    oneunit(x::T)
    oneunit(T::Type)

Return `T(one(x))`, where `T` is either the type of the argument, or
the argument itself in cases where the `oneunit` can be deduced from
the type alone. This differs from [`one`](@ref) for dimensionful
quantities: `one` is dimensionless (a multiplicative identity)
while `oneunit` is dimensionful (of the same type as `x`, or of type `T`).

# Examples
```jldoctest
julia> oneunit(3.7)
1.0

julia> import Dates; oneunit(Dates.Day)
1 day
```
"""
oneunit(x::T) where {T} = T(one(x))
oneunit(::Type{T}) where {T} = T(one(T))
oneunit(::Type{Union{}}, slurp...) = Union{}(1)

"""
    big(T::Type)

Compute the type that represents the numeric type `T` with arbitrary precision.
Equivalent to `typeof(big(zero(T)))`.

# Examples
```jldoctest
julia> big(Rational)
Rational{BigInt}

julia> big(Float64)
BigFloat

julia> big(Complex{Int})
Complex{BigInt}
```
"""
big(::Type{T}) where {T<:Number} = typeof(big(zero(T)))
big(::Type{Union{}}, slurp...) = Union{}(0)
