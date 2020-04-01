/*
 * Copyright (C) Alex Nekipelov (alex@nekipelov.net)
 * License: MIT
 */

#ifndef HTTPPARSER_REQUESTPARSER_H
#define HTTPPARSER_REQUESTPARSER_H

#include <algorithm>

#include <string.h>
#include <stdlib.h>

#include "request.h"

namespace httpparser
{

class HttpRequestParser
{
public:
    HttpRequestParser()
        : state(RequestMethodStart), contentSize(0),
          chunkSize(0), chunked(false)

    {
    }

    enum ParseResult {
        ParsingCompleted,
        ParsingIncompleted,
        ParsingError
    };

    ParseResult parse(Request &req, const char *begin, const char *end)
    {
        return consume(req, begin, end);
    }

private:
    static bool checkIfConnection(const Request::HeaderItem &item)
    {
        return strcasecmp(item.name.c_str(), "Connection") == 0;
    }

    ParseResult consume(Request &req, const char *begin, const char *end)
    {
        while( begin != end )
        {
            char input = *begin++;

            switch (state)
            {
            case RequestMethodStart:
                if( !isChar(input) || isControl(input) || isSpecial(input) )
                {
                    return ParsingError;
                }
                else
                {
                    state = RequestMethod;
                    req.method.push_back(input);
                }
                break;
            case RequestMethod:
                if( input == ' ' )
                {
                    state = RequestUriStart;
                }
                else if( !isChar(input) || isControl(input) || isSpecial(input) )
                {
                    return ParsingError;
                }
                else
                {
                    req.method.push_back(input);
                }
                break;
            case RequestUriStart:
                if( isControl(input) )
                {
                    return ParsingError;
                }
                else
                {
                    state = RequestUri;
                    req.uri.push_back(input);
                }
                break;
            case RequestUri:
                if( input == ' ' )
                {
                    state = RequestHttpVersion_h;
                }
                else if (input == '\r')
                {
                    req.versionMajor = 0;
                    req.versionMinor = 9;

                    return ParsingCompleted;
                }
                else if( isControl(input) )
                {
                    return ParsingError;
                }
                else
                {
                    req.uri.push_back(input);
                }
                break;
            case RequestHttpVersion_h:
                if( input == 'H' )
                {
                    state = RequestHttpVersion_ht;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case RequestHttpVersion_ht:
                if( input == 'T' )
                {
                    state = RequestHttpVersion_htt;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case RequestHttpVersion_htt:
                if( input == 'T' )
                {
                    state = RequestHttpVersion_http;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case RequestHttpVersion_http:
                if( input == 'P' )
                {
                    state = RequestHttpVersion_slash;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case RequestHttpVersion_slash:
                if( input == '/' )
                {
                    req.versionMajor = 0;
                    req.versionMinor = 0;
                    state = RequestHttpVersion_majorStart;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case RequestHttpVersion_majorStart:
                if( isDigit(input) )
                {
                    req.versionMajor = input - '0';
                    state = RequestHttpVersion_major;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case RequestHttpVersion_major:
                if( input == '.' )
                {
                    state = RequestHttpVersion_minorStart;
                }
                else if (isDigit(input))
                {
                    req.versionMajor = req.versionMajor * 10 + input - '0';
                }
                else
                {
                    return ParsingError;
                }
                break;
            case RequestHttpVersion_minorStart:
                if( isDigit(input) )
                {
                    req.versionMinor = input - '0';
                    state = RequestHttpVersion_minor;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case RequestHttpVersion_minor:
                if( input == '\r' )
                {
                    state = ResponseHttpVersion_newLine;
                }
                else if( isDigit(input) )
                {
                    req.versionMinor = req.versionMinor * 10 + input - '0';
                }
                else
                {
                    return ParsingError;
                }
                break;
            case ResponseHttpVersion_newLine:
                if( input == '\n' )
                {
                    state = HeaderLineStart;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case HeaderLineStart:
                if( input == '\r' )
                {
                    state = ExpectingNewline_3;
                }
                else if( !req.headers.empty() && (input == ' ' || input == '\t') )
                {
                    state = HeaderLws;
                }
                else if( !isChar(input) || isControl(input) || isSpecial(input) )
                {
                    return ParsingError;
                }
                else
                {
                    req.headers.push_back(Request::HeaderItem());
                    req.headers.back().name.reserve(16);
                    req.headers.back().value.reserve(16);
                    req.headers.back().name.push_back(input);
                    state = HeaderName;
                }
                break;
            case HeaderLws:
                if( input == '\r' )
                {
                    state = ExpectingNewline_2;
                }
                else if( input == ' ' || input == '\t' )
                {
                }
                else if( isControl(input) )
                {
                    return ParsingError;
                }
                else
                {
                    state = HeaderValue;
                    req.headers.back().value.push_back(input);
                }
                break;
            case HeaderName:
                if( input == ':' )
                {
                    state = SpaceBeforeHeaderValue;
                }
                else if( !isChar(input) || isControl(input) || isSpecial(input) )
                {
                    return ParsingError;
                }
                else
                {
                    req.headers.back().name.push_back(input);
                }
                break;
            case SpaceBeforeHeaderValue:
                if( input == ' ' )
                {
                    state = HeaderValue;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case HeaderValue:
                if( input == '\r' )
                {
                    if( req.method == "POST" || req.method == "PUT" )
                    {
                        Request::HeaderItem &h = req.headers.back();

                        if( strcasecmp(h.name.c_str(), "Content-Length") == 0 )
                        {
                            contentSize = atoi(h.value.c_str());
                            req.content.reserve( contentSize );
                        }
                        else if( strcasecmp(h.name.c_str(), "Transfer-Encoding") == 0 )
                        {
                            if(strcasecmp(h.value.c_str(), "chunked") == 0)
                                chunked = true;
                        }
                    }
                    state = ExpectingNewline_2;
                }
                else if( isControl(input) )
                {
                    return ParsingError;
                }
                else
                {
                    req.headers.back().value.push_back(input);
                }
                break;
            case ExpectingNewline_2:
                if( input == '\n' )
                {
                    state = HeaderLineStart;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case ExpectingNewline_3: {
                std::vector<Request::HeaderItem>::iterator it = std::find_if(req.headers.begin(),
                                                                    req.headers.end(),
                                                                    checkIfConnection);

                if( it != req.headers.end() )
                {
                    if( strcasecmp(it->value.c_str(), "Keep-Alive") == 0 )
                    {
                        req.keepAlive = true;
                    }
                    else  // == Close
                    {
                        req.keepAlive = false;
                    }
                }
                else
                {
                    if( req.versionMajor > 1 || (req.versionMajor == 1 && req.versionMinor == 1) )
                        req.keepAlive = true;
                }

                if( chunked )
                {
                    state = ChunkSize;
                }
                else if( contentSize == 0 )
                {
                    if( input == '\n')
                        return ParsingCompleted;
                    else
                        return ParsingError;
                }
                else
                {
                    state = Post;
                }
                break;
            }
            case Post:
                --contentSize;
                req.content.push_back( input );

                if( contentSize == 0 )
                {
                    return ParsingCompleted;
                }
                break;
            case ChunkSize:
                if( isalnum(input) )
                {
                    chunkSizeStr.push_back(input);
                }
                else if( input == ';' )
                {
                    state = ChunkExtensionName;
                }
                else if( input == '\r' )
                {
                    state = ChunkSizeNewLine;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case ChunkExtensionName:
                if( isalnum(input) || input == ' ' )
                {
                    // skip
                }
                else if( input == '=' )
                {
                    state = ChunkExtensionValue;
                }
                else if( input == '\r' )
                {
                    state = ChunkSizeNewLine;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case ChunkExtensionValue:
                if( isalnum(input) || input == ' ' )
                {
                    // skip
                }
                else if( input == '\r' )
                {
                    state = ChunkSizeNewLine;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case ChunkSizeNewLine:
                if( input == '\n' )
                {
                    chunkSize = strtol(chunkSizeStr.c_str(), NULL, 16);
                    chunkSizeStr.clear();
                    req.content.reserve(req.content.size() + chunkSize);

                    if( chunkSize == 0 )
                        state = ChunkSizeNewLine_2;
                    else
                        state = ChunkData;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case ChunkSizeNewLine_2:
                if( input == '\r' )
                {
                    state = ChunkSizeNewLine_3;
                }
                else if( isalpha(input) )
                {
                    state = ChunkTrailerName;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case ChunkSizeNewLine_3:
                if( input == '\n' )
                {
                    return ParsingCompleted;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case ChunkTrailerName:
                if( isalnum(input) )
                {
                    // skip
                }
                else if( input == ':' )
                {
                    state = ChunkTrailerValue;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case ChunkTrailerValue:
                if( isalnum(input) || input == ' ' )
                {
                    // skip
                }
                else if( input == '\r' )
                {
                    state = ChunkSizeNewLine;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case ChunkData:
                req.content.push_back(input);

                if( --chunkSize == 0 )
                {
                    state = ChunkDataNewLine_1;
                }
                break;
            case ChunkDataNewLine_1:
                if( input == '\r' )
                {
                    state = ChunkDataNewLine_2;
                }
                else
                {
                    return ParsingError;
                }
                break;
            case ChunkDataNewLine_2:
                if( input == '\n' )
                {
                    state = ChunkSize;
                }
                else
                {
                    return ParsingError;
                }
                break;
            default:
                return ParsingError;
            }
        }

        return ParsingIncompleted;
    }

    // Check if a byte is an HTTP character.
    inline bool isChar(int c)
    {
        return c >= 0 && c <= 127;
    }

    // Check if a byte is an HTTP control character.
    inline bool isControl(int c)
    {
        return (c >= 0 && c <= 31) || (c == 127);
    }

    // Check if a byte is defined as an HTTP special character.
    inline bool isSpecial(int c)
    {
        switch (c)
        {
        case '(': case ')': case '<': case '>': case '@':
        case ',': case ';': case ':': case '\\': case '"':
        case '/': case '[': case ']': case '?': case '=':
        case '{': case '}': case ' ': case '\t':
            return true;
        default:
            return false;
        }
    }

    // Check if a byte is a digit.
    inline bool isDigit(int c)
    {
        return c >= '0' && c <= '9';
    }

    // The current state of the parser.
    enum State
    {
        RequestMethodStart,
        RequestMethod,
        RequestUriStart,
        RequestUri,
        RequestHttpVersion_h,
        RequestHttpVersion_ht,
        RequestHttpVersion_htt,
        RequestHttpVersion_http,
        RequestHttpVersion_slash,
        RequestHttpVersion_majorStart,
        RequestHttpVersion_major,
        RequestHttpVersion_minorStart,
        RequestHttpVersion_minor,

        ResponseStatusStart,
        ResponseHttpVersion_ht,
        ResponseHttpVersion_htt,
        ResponseHttpVersion_http,
        ResponseHttpVersion_slash,
        ResponseHttpVersion_majorStart,
        ResponseHttpVersion_major,
        ResponseHttpVersion_minorStart,
        ResponseHttpVersion_minor,
        ResponseHttpVersion_spaceAfterVersion,
        ResponseHttpVersion_statusCodeStart,
        ResponseHttpVersion_spaceAfterStatusCode,
        ResponseHttpVersion_statusTextStart,
        ResponseHttpVersion_newLine,

        HeaderLineStart,
        HeaderLws,
        HeaderName,
        SpaceBeforeHeaderValue,
        HeaderValue,
        ExpectingNewline_2,
        ExpectingNewline_3,

        Post,
        ChunkSize,
        ChunkExtensionName,
        ChunkExtensionValue,
        ChunkSizeNewLine,
        ChunkSizeNewLine_2,
        ChunkSizeNewLine_3,
        ChunkTrailerName,
        ChunkTrailerValue,

        ChunkDataNewLine_1,
        ChunkDataNewLine_2,
        ChunkData,
    } state;

    size_t contentSize;
    std::string chunkSizeStr;
    size_t chunkSize;
    bool chunked;
};

} // namespace httpparser

#endif // LIBAHTTP_REQUESTPARSER_H
