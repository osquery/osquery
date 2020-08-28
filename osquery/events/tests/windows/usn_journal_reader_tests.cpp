/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include "osquery/events/windows/usn_journal_reader.h"
#include "osquery/tests/test_util.h"

namespace osquery {
class UsnJournalReaderTests : public testing::Test {};

TEST_F(UsnJournalReaderTests, test_get_native_file_id) {
  USNFileReferenceNumber usn_file_ref{0x00BBFF66};
  FILE_ID_DESCRIPTOR file_id;
  GetNativeFileIdFromUSNReference(file_id, usn_file_ref);
  ASSERT_TRUE(file_id.Type == ObjectIdType || file_id.Type == FileIdType);

  if (file_id.Type == ObjectIdType) {
    EXPECT_EQ(std::memcmp(&file_id.ObjectId,
                          usn_file_ref.data.data(),
                          usn_file_ref.data.size()),
              0);
  } else if (file_id.Type == FileIdType) {
    EXPECT_EQ(file_id.FileId.QuadPart, 0x00BBFF66)
        << "in hex: " << std::hex << file_id.FileId.QuadPart;
  }
}

TEST_F(UsnJournalReaderTests, test_Get_update_sequence_number) {
  USN usn = {};
  USN_RECORD_V2 usn_v2 = {};
  usn_v2.MajorVersion = 2U;
  usn_v2.Usn = 1;
  EXPECT_TRUE(USNParsers::GetUpdateSequenceNumber(usn, (USN_RECORD*)&usn_v2));
  EXPECT_EQ(usn, 1);

  USN_RECORD_V3 usn_v3 = {};
  usn_v3.MajorVersion = 3U;
  usn_v3.Usn = 2;
  EXPECT_TRUE(USNParsers::GetUpdateSequenceNumber(usn, (USN_RECORD*)&usn_v3));
  EXPECT_EQ(usn, 2);

  usn_v3.MajorVersion = 4U;
  EXPECT_FALSE(USNParsers::GetUpdateSequenceNumber(usn, (USN_RECORD*)&usn_v3));
}

TEST_F(UsnJournalReaderTests, test_get_file_ref_number) {
  USNFileReferenceNumber ref;
  USN_RECORD_V2 usn_v2 = {};
  usn_v2.MajorVersion = 2U;
  usn_v2.FileReferenceNumber = 0x00112233;
  EXPECT_TRUE(USNParsers::GetFileReferenceNumber(ref, &usn_v2));

  ref = 0x00112233;
  USN_RECORD_V3 usn_v3 = {};
  usn_v3.MajorVersion = 3U;
  for (auto i = 0U; i < sizeof(FILE_ID_128::Identifier) && i < ref.data.size();
       i++) {
    usn_v3.FileReferenceNumber.Identifier[i] = ref.data[i];
  }
  EXPECT_TRUE(USNParsers::GetFileReferenceNumber(ref, (USN_RECORD*)&usn_v3));

  usn_v3.MajorVersion = 4U;
  EXPECT_FALSE(USNParsers::GetFileReferenceNumber(ref, (USN_RECORD*)&usn_v3));
}

TEST_F(UsnJournalReaderTests, test_get_parent_file_ref) {
  USNFileReferenceNumber ref_num;
  USN_RECORD_V2 usn_v2 = {};
  usn_v2.MajorVersion = 2U;
  usn_v2.ParentFileReferenceNumber = 5;
  EXPECT_TRUE(
      USNParsers::GetParentFileReferenceNumber(ref_num, (USN_RECORD*)&usn_v2));

  ref_num = 0x00FFBB66;
  USN_RECORD_V3 usn_v3 = {};
  usn_v3.MajorVersion = 3U;
  for (auto i = 0U;
       i < sizeof(FILE_ID_128::Identifier) && i < ref_num.data.size();
       i++) {
    usn_v3.ParentFileReferenceNumber.Identifier[i] = ref_num.data[i];
  }
  EXPECT_TRUE(
      USNParsers::GetParentFileReferenceNumber(ref_num, (USN_RECORD*)&usn_v3));

  usn_v3.MajorVersion = 4U;
  EXPECT_FALSE(
      USNParsers::GetParentFileReferenceNumber(ref_num, (USN_RECORD*)&usn_v3));
}

TEST_F(UsnJournalReaderTests, test_get_timestamp) {
  std::time_t timestamp;
  USN_RECORD_V2 usn_v2 = {};
  usn_v2.MajorVersion = 2U;
  usn_v2.TimeStamp.QuadPart = 11644473600ULL * 10000000ULL;

  EXPECT_TRUE(USNParsers::GetTimeStamp(timestamp, (USN_RECORD*)&usn_v2));
  EXPECT_EQ(timestamp, 0);

  USN_RECORD_V3 usn_v3 = {};
  usn_v3.MajorVersion = 3U;
  usn_v3.TimeStamp.QuadPart = 11644473600ULL * 10000000ULL;

  EXPECT_TRUE(USNParsers::GetTimeStamp(timestamp, (USN_RECORD*)&usn_v3));
  EXPECT_EQ(timestamp, 0);

  usn_v3.MajorVersion = 4U;
  EXPECT_FALSE(USNParsers::GetTimeStamp(timestamp, (USN_RECORD*)&usn_v3));
}

TEST_F(UsnJournalReaderTests, test_get_attributes) {
  DWORD attributes;
  USN_RECORD_V2 usn_v2 = {};
  usn_v2.MajorVersion = 2U;

  usn_v2.FileAttributes = 0x00112233;
  EXPECT_TRUE(USNParsers::GetAttributes(attributes, (USN_RECORD*)&usn_v2));
  EXPECT_EQ(attributes, 0x00112233);

  USN_RECORD_V3 usn_v3 = {};
  usn_v3.MajorVersion = 3U;

  usn_v3.FileAttributes = 0x01234567;
  EXPECT_TRUE(USNParsers::GetAttributes(attributes, (USN_RECORD*)&usn_v3));
  EXPECT_EQ(attributes, 0x01234567);

  usn_v3.MajorVersion = 4U;
  EXPECT_FALSE(USNParsers::GetAttributes(attributes, (USN_RECORD*)&usn_v3));
}

TEST_F(UsnJournalReaderTests, test_get_reason) {
  DWORD reason;
  USN_RECORD_V2 usn_v2 = {};
  usn_v2.MajorVersion = 2U;

  usn_v2.Reason = 0x00112233;
  EXPECT_TRUE(USNParsers::GetReason(reason, (USN_RECORD*)&usn_v2));
  EXPECT_EQ(reason, 0x00112233);

  USN_RECORD_V3 usn_v3 = {};
  usn_v3.MajorVersion = 3U;

  usn_v3.Reason = 0x01234567;
  EXPECT_TRUE(USNParsers::GetReason(reason, (USN_RECORD*)&usn_v3));
  EXPECT_EQ(reason, 0x01234567);

  usn_v3.MajorVersion = 4U;
  EXPECT_FALSE(USNParsers::GetReason(reason, (USN_RECORD*)&usn_v3));
}

TEST_F(UsnJournalReaderTests, test_get_event_type) {
  USNJournalEventRecord::Type type;

  DWORD reason_bit = USN_REASON_FILE_CREATE;
  DWORD journal_file_attributes = FILE_ATTRIBUTE_DIRECTORY;
  EXPECT_TRUE(
      USNParsers::GetEventType(type, reason_bit, journal_file_attributes));
  EXPECT_EQ(type, USNJournalEventRecord::Type::DirectoryCreation);

  journal_file_attributes = FILE_ATTRIBUTE_NORMAL;
  EXPECT_TRUE(
      USNParsers::GetEventType(type, reason_bit, journal_file_attributes));
  EXPECT_EQ(type, USNJournalEventRecord::Type::FileCreation);

  // NOTE(ww): All bits 0 is currently unused, but NTFS doesn't guarantee that
  // it will remain unused.
  reason_bit = 0;
  EXPECT_FALSE(
      USNParsers::GetEventType(type, reason_bit, journal_file_attributes));
}

TEST_F(UsnJournalReaderTests, test_get_event_string) {
  std::string buffer;

  uint8_t scratch[4096] = {};

  USN_RECORD_V2* usn_v2 = (USN_RECORD_V2*)scratch;
  wchar_t* event_string_v2 = L"foo foo foo";

  usn_v2->MajorVersion = 2U;
  usn_v2->FileNameOffset = sizeof(USN_RECORD_V2);
  usn_v2->FileNameLength = (WORD)(wcslen(event_string_v2) * sizeof(wchar_t));
  usn_v2->RecordLength =
      (DWORD)(sizeof(USN_RECORD_V2) + usn_v2->FileNameLength);
  memcpy(usn_v2->FileName, event_string_v2, usn_v2->FileNameLength);
  EXPECT_TRUE(USNParsers::GetEventString(buffer, (USN_RECORD*)usn_v2))
      << "GetEventString should parse V2 records";
  EXPECT_EQ(buffer, "foo foo foo") << "event string should match input";

  memset(scratch, 0, sizeof(scratch));
  USN_RECORD_V3* usn_v3 = (USN_RECORD_V3*)scratch;
  wchar_t* event_string_v3 = L"bar bar bar";

  usn_v3->MajorVersion = 3U;
  usn_v3->FileNameOffset = sizeof(USN_RECORD_V3);
  usn_v3->FileNameLength = (WORD)(wcslen(event_string_v3) * sizeof(wchar_t));
  usn_v3->RecordLength =
      (DWORD)(sizeof(USN_RECORD_V3) + usn_v3->FileNameLength);
  memcpy(usn_v3->FileName, event_string_v3, usn_v3->FileNameLength);
  EXPECT_TRUE(USNParsers::GetEventString(buffer, (USN_RECORD*)usn_v3))
      << "GetEventString should parse V3 records";
  EXPECT_EQ(buffer, "bar bar bar") << "event string should match input";

  usn_v3->FileNameLength = 0U;
  EXPECT_TRUE(USNParsers::GetEventString(buffer, (USN_RECORD*)usn_v3));
  EXPECT_EQ(buffer, "") << "zero-length filename should be empty";

  usn_v3->MajorVersion = 4U;
  EXPECT_FALSE(USNParsers::GetEventString(buffer, (USN_RECORD*)usn_v3))
      << "GetEventString should refuse to parse V4 records";
}
} // namespace osquery
