#include <gtest/gtest.h>

#include "osquery/events/windows/usn_journal_reader.h"
#include "osquery/tests/test_util.h"

namespace osquery {
class UsnJournalReaderTests : public testing::Test {};

TEST_F(UsnJournalReaderTests, test_get_native_file_id) {
  USNFileReferenceNumber usn_file_ref = 0x00BBFF66;
  FILE_ID_DESCRIPTOR file_id;
  GetNativeFileIdFromUSNReference(file_id, usn_file_ref);
  ASSERT_TRUE(file_id.Type == ExtendedFileIdType || file_id.Type == FileIdType);

  if (file_id.Type == ExtendedFileIdType) {
    std::vector<unsigned char> buffer(sizeof(FILE_ID_128::Identifier));
    boostmp::export_bits(usn_file_ref, std::back_inserter(buffer), 8, false);
    while (buffer.size() > sizeof(FILE_ID_128::Identifier))
      buffer.erase(buffer.begin());
    for (auto i = 0U; i < sizeof(FILE_ID_128::Identifier) && i < buffer.size();
         ++i) {
      EXPECT_EQ(buffer[i], file_id.ExtendedFileId.Identifier[i])
          << "values differ at index " << i;
    }
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
  EXPECT_EQ(ref, 0x00112233);

  ref = 0x00112233;
  USN_RECORD_V3 usn_v3 = {};
  usn_v3.MajorVersion = 3U;
  std::vector<unsigned char> buffer;
  boostmp::export_bits(ref, std::back_inserter(buffer), 8, false);
  buffer.resize(sizeof(FILE_ID_128::Identifier));
  for (auto i = 0U; i < sizeof(FILE_ID_128::Identifier) && i < buffer.size();
       i++) {
    usn_v3.FileReferenceNumber.Identifier[i] = buffer[i];
  }
  EXPECT_TRUE(USNParsers::GetFileReferenceNumber(ref, (USN_RECORD*)&usn_v3));
  EXPECT_EQ(ref, 0x00112233);

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
  EXPECT_EQ(ref_num, 5);

  ref_num = 0x00FFBB66;
  USN_RECORD_V3 usn_v3 = {};
  usn_v3.MajorVersion = 3U;
  std::vector<unsigned char> buffer;
  boostmp::export_bits(ref_num, std::back_inserter(buffer), 8, false);
  buffer.resize(sizeof(FILE_ID_128::Identifier));
  for (auto i = 0U; i < sizeof(FILE_ID_128::Identifier) && i < buffer.size();
       i++) {
    usn_v3.ParentFileReferenceNumber.Identifier[i] = buffer[i];
  }
  EXPECT_TRUE(
      USNParsers::GetParentFileReferenceNumber(ref_num, (USN_RECORD*)&usn_v3));
  EXPECT_EQ(ref_num, 0x00FFBB66);

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

/*
bool GetEventType(USNJournalEventRecord::Type& type,
                  DWORD reason_bit,
                  DWORD journal_file_attributes);

bool GetEventString(std::string& buffer, const USN_RECORD* record);
*/
} // namespace osquery
