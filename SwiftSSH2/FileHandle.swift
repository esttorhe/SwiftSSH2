
// Native Frameworks
import Foundation

//CK2SFTPFileHandle : NSFileHandle
//{
//    @private
//    LIBSSH2_SFTP_HANDLE *_handle;
//    CK2SFTPSession      *_session;
//    NSString            *_path;
//    }
//    
//    // Session reference & path are not compulsary, but without you won't get decent error information
//    - (id)initWithSFTPHandle:(LIBSSH2_SFTP_HANDLE *)handle session:(CK2SFTPSession *)session path:(NSString *)path;
//
//- (BOOL)closeFile:(NSError **)error;
//
//- (BOOL)writeData:(NSData *)data error:(NSError **)error;
//- (NSInteger)write:(const uint8_t *)buffer maxLength:(NSUInteger)length error:(NSError **)error;
//- (NSInteger)write:(const uint8_t *)buffer maxLength:(NSUInteger)length;

public class FileHandle : NSFileHandle {
//  private var handle: LIBSSH2_SFTP_HANDLE
}