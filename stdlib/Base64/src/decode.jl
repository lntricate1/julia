# This file is a part of Julia. License is MIT: https://julialang.org/license

# Generate decode table.
const BASE64_CODE_END = 0x40
const BASE64_CODE_PAD = 0x41
const BASE64_CODE_IGN = 0x42
const BASE64_DECODE = fill(BASE64_CODE_IGN, 256)
for (i, c) in enumerate(BASE64_ENCODE)
    BASE64_DECODE[Int(c)+1] = UInt8(i - 1)
end
BASE64_DECODE[Int(encodepadding())+1] = BASE64_CODE_PAD
decode(x::UInt8) = @inbounds return BASE64_DECODE[x + 1]

const BASE64_DECODE_32 = UInt32.(BASE64_DECODE)
# Given (A, B, C, D) decodes into aaaaaabb_bbbbcccc_ccdddddd_xxxxxxxx
@inline function decode_4(x::Tuple{UInt8, UInt8, UInt8, UInt8})
  b1 = @inbounds BASE64_DECODE_32[x[1] + 1]
  b2 = @inbounds BASE64_DECODE_32[x[2] + 1]
  b3 = @inbounds BASE64_DECODE_32[x[3] + 1]
  b4 = @inbounds BASE64_DECODE_32[x[4] + 1]
  (b1 >= 0x40 || b2 >= 0x40 || b3 >= 0x40 || b4 >= 0x40) &&
      throw(ArgumentError("malformed base64 sequence; invalid base64 character"))
  return b1 << 26 | b2 << 20 | b3 << 14 | b4 << 8
end

"""
    Base64DecodePipe(istream)

Return a new read-only I/O stream, which decodes base64-encoded data read from
`istream`.

# Examples
```jldoctest
julia> io = IOBuffer();

julia> iob64_decode = Base64DecodePipe(io);

julia> write(io, "SGVsbG8h")
8

julia> seekstart(io);

julia> String(read(iob64_decode))
"Hello!"
```
"""
struct Base64DecodePipe <: IO
    io::IO
    buffer::Buffer
    rest::Vector{UInt8}

    function Base64DecodePipe(io::IO)
        buffer = Buffer(512)
        return new(io, buffer, UInt8[])
    end
end

Base.isreadable(pipe::Base64DecodePipe) = !isempty(pipe.rest) || isreadable(pipe.io)
Base.iswritable(::Base64DecodePipe) = false

function Base.unsafe_read(pipe::Base64DecodePipe, ptr::Ptr{UInt8}, n::UInt)
    p = read_until_end(pipe, ptr, n)
    if p < ptr + n
        throw(EOFError())
    end
    return nothing
end

# Read and decode as much data as possible.
function read_until_end(pipe::Base64DecodePipe, ptr::Ptr{UInt8}, n::UInt)
    p = ptr
    p_end = ptr + n
    while !isempty(pipe.rest) && p < p_end
        unsafe_store!(p, popfirst!(pipe.rest))
        p += 1
    end

    buffer = pipe.buffer
    i = 0
    b1 = b2 = b3 = b4 = BASE64_CODE_IGN
    while true
        if b1 < 0x40 && b2 < 0x40 && b3 < 0x40 && b4 < 0x40 && p + 2 < p_end
            # fast path to decode
            unsafe_store!(p    , b1 << 2 | b2 >> 4)
            unsafe_store!(p + 1, b2 << 4 | b3 >> 2)
            unsafe_store!(p + 2, b3 << 6 | b4     )
            p += 3
        else
            i, p, ended = decode_slow(b1, b2, b3, b4, buffer, i, pipe.io, p, p_end - p, pipe.rest)
            if ended
                break
            end
        end
        if p < p_end
            if i + 4 ≤ lastindex(buffer)
                b1 = decode(buffer[i+1])
                b2 = decode(buffer[i+2])
                b3 = decode(buffer[i+3])
                b4 = decode(buffer[i+4])
                i += 4
            else
                consumed!(buffer, i)
                read_to_buffer(pipe.io, buffer)
                i = 0
                b1 = b2 = b3 = b4 = BASE64_CODE_IGN
            end
        else
            break
        end
    end
    consumed!(buffer, i)

    return p
end

function Base.read(pipe::Base64DecodePipe, ::Type{UInt8})
    if isempty(pipe.rest)
        unsafe_read(pipe, convert(Ptr{UInt8}, C_NULL), 0)
        if isempty(pipe.rest)
            throw(EOFError())
        end
    end
    return popfirst!(pipe.rest)
end

function Base.readbytes!(pipe::Base64DecodePipe, data::AbstractVector{UInt8}, nb::Integer=length(data))
    require_one_based_indexing(data)
    filled::Int = 0
    while filled < nb && !eof(pipe)
        if length(data) == filled
            resize!(data, min(length(data) * 2, nb))
        end
        p = pointer(data, filled + 1)
        p_end = read_until_end(pipe, p, UInt(min(length(data), nb) - filled))
        filled += p_end - p
    end
    resize!(data, filled)
    return filled
end

Base.eof(pipe::Base64DecodePipe) = isempty(pipe.rest) && eof(pipe.io)::Bool
Base.close(pipe::Base64DecodePipe) = nothing

# Decode data from (b1, b2, b3, b5, buffer, input) into (ptr, rest).
function decode_slow(b1, b2, b3, b4, buffer, i, input, ptr, n, rest)
    # Skip ignore code.
    while true
        if b1 == BASE64_CODE_IGN
            b1, b2, b3 = b2, b3, b4
        elseif b2 == BASE64_CODE_IGN
            b2, b3 = b3, b4
        elseif b3 == BASE64_CODE_IGN
            b3 = b4
        elseif b4 == BASE64_CODE_IGN
            # pass
        else
            break
        end
        if i + 1 ≤ lastindex(buffer)
            b4 = decode(buffer[i+=1])
        elseif !eof(input)
            b4 = decode(read(input, UInt8))
        else
            b4 = BASE64_CODE_END
        end
    end

    # Check the decoded quadruplet.
    k = 0
    if b1 < 0x40 && b2 < 0x40 && b3 < 0x40 && b4 < 0x40
        k = 3
    elseif b1 < 0x40 && b2 < 0x40 && b3 < 0x40 && (b4 == BASE64_CODE_PAD || b4 == BASE64_CODE_END)
        b4 = 0x00
        k = 2
    elseif b1 < 0x40 && b2 < 0x40 && (b3 == BASE64_CODE_PAD || b3 == BASE64_CODE_END) && (b4 == BASE64_CODE_PAD || b4 == BASE64_CODE_END)
        b3 = b4 = 0x00
        k = 1
    elseif b1 == b2 == b3 == b4 == BASE64_CODE_END
        b1 = b2 = b3 = b4 = 0x00
    else
        throw(ArgumentError("malformed base64 sequence"))
    end

    # Write output.
    p::Ptr{UInt8} = ptr
    p_end = ptr + n
    function output(b)
        if p < p_end
            unsafe_store!(p, b)
            p += 1
        else
            push!(rest, b)
        end
    end
    k ≥ 1 && output(b1 << 2 | b2 >> 4)
    k ≥ 2 && output(b2 << 4 | b3 >> 2)
    k ≥ 3 && output(b3 << 6 | b4     )

    return i, p, k == 0
end

"""
    base64decode(string)

Decode the base64-encoded `string` and return a `Vector{UInt8}` of the decoded
bytes.

See also [`base64encode`](@ref).

# Examples
```jldoctest
julia> b = base64decode("SGVsbG8h")
6-element Vector{UInt8}:
 0x48
 0x65
 0x6c
 0x6c
 0x6f
 0x21

julia> String(b)
"Hello!"
```
"""
function base64decode(s::String)
    in_len = sizeof(s)
    out_len = unsafe_base64decode_length(pointer(s), in_len)
    output = Vector{UInt8}(undef, out_len)
    GC.@preserve s output begin
        unsafe_base64decode!(pointer(output), pointer(s), in_len)
    end
    return output
end

"""
base64decode(data::AbstractVector{UInt8})

Decode the base64-encoded `data` and return a `Vector{UInt8}` of the decoded
bytes.

See also [`base64encode`](@ref).

# Examples
```jldoctest
julia> b = base64decode(b"SGVsbG8h")
6-element Vector{UInt8}:
 0x48
 0x65
 0x6c
 0x6c
 0x6f
 0x21

julia> String(b)
"Hello!"
```
"""
function base64decode(s)
    b = IOBuffer(s)
    try
        return read(Base64DecodePipe(b))
    finally
        close(b)
    end
end

# A more efficient implementation of base64decode(::DenseVector)
function base64decode(input::DenseVector{UInt8})
    in_len = length(input)
    out_len = unsafe_base64decode_length(pointer(input), in_len)
    output = Vector{UInt8}(undef, out_len)
    GC.@preserve input output begin
        unsafe_base64decode!(pointer(output), pointer(input), in_len)
    end
    return output
end

"""
    unsafe_base64decode_length(input::Ptr, in_len::Integer)

Determine the expected length of base64 decoding the data in `input`.

The unsafe prefix on this function indicates that no validation is performed on the pointer `input` to ensure that it is valid. Like C, the programmer is responsible for ensuring that referenced memory is not freed or garbage collected while invoking this function. Incorrect usage may segfault your program.
"""
function unsafe_base64decode_length(input::Ptr, in_len::Integer)
  in_len == 0 && return 0
  d, r = divrem(in_len, 4)
  r == 1 && throw(ArgumentError("malformed base64 sequence; invalid length"))
  r == 2 && return 3d + 1
  r == 3 && return decode(unsafe_load(Ptr{UInt8}(input), in_len)) >= 0x40 ? 3d + 1 : 3d + 2
  return decode(unsafe_load(Ptr{UInt8}(input), in_len)) < 0x40 ? 3d :
      decode(unsafe_load(Ptr{UInt8}(input), 4d - 1)) < 0x40 ? 3d - 1 : 3d - 2
end

"""
    unsafe_base64encode!(output::Ptr, input::Ptr, in_len)

Base64-encode `in_len` bytes from `input` and write to `output`. Assumes `output` is large enough (at least `3*cld(in_len, 4)`, or 1 or 2 bytes less if the input ends with padding).

The unsafe prefix on this function indicates that no validation is performed on the pointers `input` and `output` to ensure that they are valid. Like C, the programmer is responsible for ensuring that referenced memory is not freed or garbage collected while invoking this function. Incorrect usage may segfault your program.
"""
function unsafe_base64decode!(output::Ptr, input::Ptr, in_len::Integer)
    in_len == 0 && return nothing
    op = Ptr{UInt32}(output)
    ip = Ptr{Tuple{UInt8, UInt8, UInt8, UInt8}}(input)
    in_ending = ip + in_len
    # Unrolling the loop like this gives ~2x speed increase
    while ip + (64+4) < in_ending
        unsafe_store!(op   , unsafe_load(ip   ) |> decode_4 |> ntoh)
        unsafe_store!(op+3 , unsafe_load(ip+4 ) |> decode_4 |> ntoh)
        unsafe_store!(op+6 , unsafe_load(ip+8 ) |> decode_4 |> ntoh)
        unsafe_store!(op+9 , unsafe_load(ip+12) |> decode_4 |> ntoh)
        unsafe_store!(op+12, unsafe_load(ip+16) |> decode_4 |> ntoh)
        unsafe_store!(op+15, unsafe_load(ip+20) |> decode_4 |> ntoh)
        unsafe_store!(op+18, unsafe_load(ip+24) |> decode_4 |> ntoh)
        unsafe_store!(op+21, unsafe_load(ip+28) |> decode_4 |> ntoh)
        unsafe_store!(op+24, unsafe_load(ip+32) |> decode_4 |> ntoh)
        unsafe_store!(op+27, unsafe_load(ip+36) |> decode_4 |> ntoh)
        unsafe_store!(op+30, unsafe_load(ip+40) |> decode_4 |> ntoh)
        unsafe_store!(op+33, unsafe_load(ip+44) |> decode_4 |> ntoh)
        unsafe_store!(op+36, unsafe_load(ip+48) |> decode_4 |> ntoh)
        unsafe_store!(op+39, unsafe_load(ip+52) |> decode_4 |> ntoh)
        unsafe_store!(op+42, unsafe_load(ip+56) |> decode_4 |> ntoh)
        unsafe_store!(op+45, unsafe_load(ip+60) |> decode_4 |> ntoh)
        ip += 64
        op += 48
    end
    while ip + 4 < in_ending
        unsafe_store!(op, unsafe_load(ip) |> decode_4 |> ntoh)
        ip += 4
        op += 3
    end

    # Read last 4 bytes
    @assert in_ending - 4 <= ip <= in_ending - 2
    b1 = decode(unsafe_load(Ptr{UInt8}(ip), 1))
    b2 = decode(unsafe_load(Ptr{UInt8}(ip), 2))
    b3 = in_ending - ip >= 3 ? decode(unsafe_load(Ptr{UInt8}(ip), 3)) : BASE64_CODE_PAD
    b4 = in_ending - ip == 4 ? decode(unsafe_load(Ptr{UInt8}(ip), 4)) : BASE64_CODE_PAD
    if b4 != BASE64_CODE_PAD
        (b1 >= 0x40 || b2 >= 0x40 || b3 >= 0x40 || b4 >= 0x40) &&
            throw(ArgumentError("malformed base64 sequence; invalid base64 character"))
        unsafe_store!(Ptr{UInt8}(op), b1 << 2 | b2 >> 4, 1)
        unsafe_store!(Ptr{UInt8}(op), b2 << 4 | b3 >> 2, 2)
        unsafe_store!(Ptr{UInt8}(op), b3 << 6 | b4     , 3)
    elseif b3 != BASE64_CODE_PAD
        (b1 >= 0x40 || b2 >= 0x40 || b3 >= 0x40) &&
            throw(ArgumentError("malformed base64 sequence; invalid base64 character"))
        unsafe_store!(Ptr{UInt8}(op), b1 << 2 | b2 >> 4, 1)
        unsafe_store!(Ptr{UInt8}(op), b2 << 4          , 2)
    else
        (b1 >= 0x40 || b2 >= 0x40) &&
            throw(ArgumentError("malformed base64 sequence; invalid base64 character"))
        unsafe_store!(Ptr{UInt8}(op), b1 << 2 | b2 >> 4)
    end
    return nothing
end
