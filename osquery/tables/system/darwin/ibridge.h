/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#import <AppKit/NSDocument.h>

@class NSArray, NSBundle, NSImage, NSMutableDictionary, NSNumberFormatter,
    NSObject, NSString;
@protocol SPDocumentDelegate;

@interface SPDocument : NSDocument {
  NSMutableDictionary* _systemProfileDictionary;
  NSMutableDictionary* _dataTypes;
  NSMutableDictionary* _detailLevelsForDataTypes;
  BOOL _loadedFromFile;
  int _detailLevel;
  int _maximumDetailLevel;
  NSArray* _localizableUnits;
  NSBundle* _frameworkBundle;
  NSNumberFormatter* _englishNumberFormatter;
  NSImage* _modelIcon;
  double _timeout;
  id _delegate;
  NSString* _selectedDataType;
}

@property double timeout; // @synthesize timeout=_timeout;
@property NSObject<SPDocumentDelegate>*
    delegate; // @synthesize delegate=_delegate;
@property(copy) NSString*
    selectedDataType; // @synthesize selectedDataType=_selectedDataType;
- (void)dealloc;
- (id)handleUploadCommand:(id)arg1;
- (BOOL)uploadToURL:(id)arg1 usingCompression:(BOOL)arg2;
- (id)printOperationWithSettings:(id)arg1 error:(id*)arg2;
- (id)dataOfType:(id)arg1 error:(id*)arg2;
- (BOOL)readFromURL:(id)arg1 ofType:(id)arg2 error:(id*)arg3;
- (id)writableTypesForSaveOperation:(unsigned long long)arg1;
- (BOOL)isLoadedFromFile;
- (void)makeWindowControllers;
- (id)modelIcon;
- (id)computerName;
- (id)serialNumber;
- (id)modelName;
- (id)richTextRepresentation;
- (id)richTextRepresentationForDataTypes:(id)arg1;
- (id)plainTextRepresentation;
- (id)plainTextRepresentationForDataTypes:(id)arg1;
- (id)xmlPropertyListRepresentation;
- (id)xmlPropertyListRepresentationForDataTypes:(id)arg1;
- (id)_xmlPropertyListRepresentationForArray:(id)arg1;
- (id)stringForDataTypes:(id)arg1;
- (id)attributedStringForDataTypes:(id)arg1;
- (id)reportHeader;
- (id)stringForItem:(id)arg1 dataType:(id)arg2;
- (id)_stringForItem:(id)arg1
            dataType:(id)arg2
         indentation:(int)arg3
              isUnit:(BOOL)arg4;
- (id)attributedStringForItem:(id)arg1 dataType:(id)arg2;
- (id)_attributedStringForItem:(id)arg1
                      dataType:(id)arg2
                   indentation:(float)arg3
                        isUnit:(BOOL)arg4;
- (id)localizedDescriptionForObject:(id)arg1 dataType:(id)arg2;
- (id)localizedStringForKey:(id)arg1 dataType:(id)arg2;
- (BOOL)shouldUseRightToLeftLayout;
- (void)refreshReports;
- (void)refreshReportForDataType:(id)arg1;
- (id)reportsForDataTypes:(id)arg1;
- (id)reportForDataType:(id)arg1;
- (id)_reportFromHelperToolForDataType:(id)arg1;
- (id)_reportFromBundlesForDataType:(id)arg1;
- (id)_setReport:(id)arg1 forDataType:(id)arg2;
- (id)orderedIdentifiersForItem:(id)arg1 dataType:(id)arg2;
- (id)propertiesForDataType:(id)arg1;
- (id)parentOfDataType:(id)arg1;
- (id)dataTypesWithParent:(id)arg1;
- (id)dataTypes;
- (void)_addDataType:(id)arg1 parent:(id)arg2 detailLevel:(int)arg3;
- (void)_enforceDetailLevelForPlist:(id)arg1 usingProperties:(id)arg2;
- (void)obscureBluetoothNames:(id)arg1;
- (int)maximumDetailLevel;
- (int)detailLevel;
- (void)setDetailLevel:(int)arg1;
- (id)init;

@end
