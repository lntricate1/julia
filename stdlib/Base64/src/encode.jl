# This file is a part of Julia. License is MIT: https://julialang.org/license

# Generate encode table.
const BASE64_ENCODE = UInt8.(['A':'Z'; 'a':'z'; '0':'9'; '+'; '/'])
# Generate encode table of pairs. This is faster for looking up 4 at a time.
const BASE64_ENCODE_2 = [UInt8.((a, b)) for a in BASE64_ENCODE for b in BASE64_ENCODE]
encode(x::UInt8) = @inbounds return BASE64_ENCODE[(x & 0x3f) + 1]
# Given aaaaaabb|bbbbcccc|ccdddddd|xxxxxxxx encodes into (A, B, C, D).
encode_4(x::UInt32) = @inbounds (
    BASE64_ENCODE_2[x>>20 + 1]..., BASE64_ENCODE_2[x>>8 & 0x0fff + 1]...)
encodepadding() = UInt8('=')

"""
    Base64EncodePipe(ostream)

Return a new write-only I/O stream, which converts any bytes written to it into
base64-encoded ASCII bytes written to `ostream`.  Calling [`close`](@ref) on the
`Base64EncodePipe` stream is necessary to complete the encoding (but does not
close `ostream`).

# Examples
```jldoctest
julia> io = IOBuffer();

julia> iob64_encode = Base64EncodePipe(io);

julia> write(iob64_encode, "Hello!")
6

julia> close(iob64_encode);

julia> str = String(take!(io))
"SGVsbG8h"

julia> String(base64decode(str))
"Hello!"
```
"""
struct Base64EncodePipe <: IO
    io::IO
    buffer::Buffer

    function Base64EncodePipe(io::IO)
        # The buffer size must be at least 3.
        buffer = Buffer(512)
        pipe = new(io, buffer)
        finalizer(_ -> close(pipe), buffer)
        return pipe
    end
end

Base.isreadable(::Base64EncodePipe) = false
Base.iswritable(pipe::Base64EncodePipe) = iswritable(pipe.io)

function Base.unsafe_write(pipe::Base64EncodePipe, ptr::Ptr{UInt8}, n::UInt)::Int
    buffer = pipe.buffer
    m = buffer.size
    b1, b2, b3, k = loadtriplet!(buffer, ptr, n)
    @assert k ≥ m
    p = ptr + k - m
    if k < 3
        if k == 1
            buffer[1] = b1
            buffer.size = 1
        elseif k == 2
            buffer[1] = b1
            buffer[2] = b2
            buffer.size = 2
        end
        return p - ptr
    end
    @assert buffer.size == 0

    i = 0
    p_end = ptr + n
    while true
        buffer[i+1] = encode(b1 >> 2          )
        buffer[i+2] = encode(b1 << 4 | b2 >> 4)
        buffer[i+3] = encode(b2 << 2 | b3 >> 6)
        buffer[i+4] = encode(          b3     )
        i += 4
        if p + 2 < p_end
            b1 = unsafe_load(p, 1)
            b2 = unsafe_load(p, 2)
            b3 = unsafe_load(p, 3)
            p += 3
        else
            break
        end
        if i + 4 > capacity(buffer)
            unsafe_write(pipe.io, pointer(buffer), i)
            i = 0
        end
    end
    if i > 0
        unsafe_write(pipe.io, pointer(buffer), i)
    end

    while p < p_end
        buffer[buffer.size+=1] = unsafe_load(p)
        p += 1
    end
    return p - ptr
end

function Base.write(pipe::Base64EncodePipe, x::UInt8)
    buffer = pipe.buffer
    buffer[buffer.size+=1] = x
    if buffer.size == 3
        unsafe_write(pipe, C_NULL, 0)
    end
    return 1
end

function Base.close(pipe::Base64EncodePipe)
    b1, b2, b3, k = loadtriplet!(pipe.buffer, Ptr{UInt8}(C_NULL), UInt(0))
    if k == 0
        # no leftover and padding
    elseif k == 1
        write(pipe.io,
              encode(b1 >> 2),
              encode(b1 << 4),
              encodepadding(),
              encodepadding())
    elseif k == 2
        write(pipe.io,
              encode(          b1 >> 2),
              encode(b1 << 4 | b2 >> 4),
              encode(b2 << 2          ),
              encodepadding())
    else
        @assert k == 3
        write(pipe.io,
              encode(b1 >> 2          ),
              encode(b1 << 4 | b2 >> 4),
              encode(b2 << 2 | b3 >> 6),
              encode(          b3     ))
    end
    return nothing
end

# Load three bytes from buffer and ptr.
function loadtriplet!(buffer::Buffer, ptr::Ptr{UInt8}, n::UInt)
    b1 = b2 = b3 = 0x00
    if buffer.size == 0
        if n == 0
            k = 0
        elseif n == 1
            b1 = unsafe_load(ptr, 1)
            k = 1
        elseif n == 2
            b1 = unsafe_load(ptr, 1)
            b2 = unsafe_load(ptr, 2)
            k = 2
        else
            b1 = unsafe_load(ptr, 1)
            b2 = unsafe_load(ptr, 2)
            b3 = unsafe_load(ptr, 3)
            k = 3
        end
    elseif buffer.size == 1
        b1 = buffer[1]
        if n == 0
            k = 1
        elseif n == 1
            b2 = unsafe_load(ptr, 1)
            k = 2
        else
            b2 = unsafe_load(ptr, 1)
            b3 = unsafe_load(ptr, 2)
            k = 3
        end
    elseif buffer.size == 2
        b1 = buffer[1]
        b2 = buffer[2]
        if n == 0
            k = 2
        else
            b3 = unsafe_load(ptr, 1)
            k = 3
        end
    else
        @assert buffer.size == 3
        b1 = buffer[1]
        b2 = buffer[2]
        b3 = buffer[3]
        k = 3
    end
    empty!(buffer)
    return b1, b2, b3, k
end

"""
    base64encode(writefunc, args...; context=nothing)
    base64encode(args...; context=nothing)

Given a [`write`](@ref)-like function `writefunc`, which takes an I/O stream as
its first argument, `base64encode(writefunc, args...)` calls `writefunc` to
write `args...` to a base64-encoded string, and returns the string.
`base64encode(args...)` is equivalent to `base64encode(write, args...)`: it
converts its arguments into bytes using the standard [`write`](@ref) functions
and returns the base64-encoded string.

The optional keyword argument `context` can be set to `:key=>value` pair
or an `IO` or [`IOContext`](@ref) object whose attributes are used for the I/O
stream passed to `writefunc` or `write`.

See also [`base64decode`](@ref).
"""
function base64encode(f::Function, args...; context=nothing)
    s = IOBuffer()
    b = Base64EncodePipe(s)
    if context === nothing
        f(b, args...)
    else
        f(IOContext(b, context), args...)
    end
    close(b)
    return String(take!(s))
end
base64encode(args...; context=nothing) = base64encode(write, args...; context=context)

# A more efficient implementation of base64encode(::DenseVector; context=nothing)
function base64encode(input::DenseVector{UInt8})
    in_len = length(input)
    out_len = 4cld(in_len, 3)
    output = Base._string_n(out_len)
    GC.@preserve input output begin
        unsafe_base64encode!(pointer(output), pointer(input), out_len, in_len)
    end
    return output
end

"""
    unsafe_base64encode!(output::Ptr, input::Ptr, out_len, in_len)

Base 64-encode data from `input` and write to `output`.

The unsafe prefix on this function indicates that no validation is performed on the pointers `input` and `output` to ensure that they are valid. Like C, the programmer is responsible for ensuring that referenced memory is not freed or garbage collected while invoking this function. Incorrect usage may segfault your program.
"""
function unsafe_base64encode!(output::Ptr{O}, input::Ptr{I}, out_len::Integer, in_len::Integer) where {O, I}
    op = Ptr{Tuple{UInt8, UInt8, UInt8, UInt8}}(output)
    ip = Ptr{UInt32}(input)
    out_ending = op + out_len
    in_ending = ip + in_len
    # Unrolling the loop like this gives ~2x speed increase
    while op + (64+4) < out_ending
        unsafe_store!(op,    unsafe_load(ip   ) |> hton |> encode_4)
        unsafe_store!(op+4,  unsafe_load(ip+3 ) |> hton |> encode_4)
        unsafe_store!(op+8,  unsafe_load(ip+6 ) |> hton |> encode_4)
        unsafe_store!(op+12, unsafe_load(ip+9 ) |> hton |> encode_4)
        unsafe_store!(op+16, unsafe_load(ip+12) |> hton |> encode_4)
        unsafe_store!(op+20, unsafe_load(ip+15) |> hton |> encode_4)
        unsafe_store!(op+24, unsafe_load(ip+18) |> hton |> encode_4)
        unsafe_store!(op+28, unsafe_load(ip+21) |> hton |> encode_4)
        unsafe_store!(op+32, unsafe_load(ip+24) |> hton |> encode_4)
        unsafe_store!(op+36, unsafe_load(ip+27) |> hton |> encode_4)
        unsafe_store!(op+40, unsafe_load(ip+30) |> hton |> encode_4)
        unsafe_store!(op+44, unsafe_load(ip+33) |> hton |> encode_4)
        unsafe_store!(op+48, unsafe_load(ip+36) |> hton |> encode_4)
        unsafe_store!(op+52, unsafe_load(ip+39) |> hton |> encode_4)
        unsafe_store!(op+56, unsafe_load(ip+42) |> hton |> encode_4)
        unsafe_store!(op+60, unsafe_load(ip+45) |> hton |> encode_4)
        op += 64
        ip += 48
    end
    while op + 4 < out_ending
        unsafe_store!(op, unsafe_load(ip) |> hton |> encode_4)
        op += 4
        ip += 3
    end

    # Write last 4 bytes
    @assert in_ending - 3 <= ip <= in_ending
    l = in_ending - ip
    if l == 3
        b1 = unsafe_load(Ptr{UInt8}(ip))
        b2 = unsafe_load(Ptr{UInt8}(ip), 2)
        b3 = unsafe_load(Ptr{UInt8}(ip), 3)
        unsafe_store!(op, (
            encode(b1 >> 2          ),
            encode(b1 << 4 | b2 >> 4),
            encode(b2 << 2 | b3 >> 6),
            encode(          b3     )
        ))
    elseif l == 2
        b1 = unsafe_load(Ptr{UInt8}(ip))
        b2 = unsafe_load(Ptr{UInt8}(ip), 2)
        unsafe_store!(op, (
            encode(b1 >> 2          ),
            encode(b1 << 4 | b2 >> 4),
            encode(b2 << 2          ),
            encodepadding()
        ))
    elseif l == 1
        b1 = unsafe_load(Ptr{UInt8}(ip))
        unsafe_store!(op, (
            encode(b1 >> 2          ),
            encode(b1 << 4          ),
            encodepadding(), encodepadding()
        ))
    end
    return nothing
end
