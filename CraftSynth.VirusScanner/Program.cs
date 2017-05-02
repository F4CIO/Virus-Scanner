using System;
using System.CodeDom;
using System.IO;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using CraftSynth.BuildingBlocks.Common;
using CraftSynth.BuildingBlocks.IO;
using CraftSynth.BuildingBlocks.Logging;
using Ionic.Zip;

namespace CraftSynth.VirusScanner
{
	class Program
	{
		private const int whichNumberToReturnIfErrorOccured = -1;
		static int Main(string[] args)
		{
			int? r = null;	

			BuildingBlocks.Logging.CustomTraceLog log = new CustomTraceLog("Starting...----------------------------------------------------------------------------------------------------------", true, false, CustomTraceLogAddLinePostProcessingEvent);
			try
			{
				DateTime now = DateTime.Now;
				string nowUniqueString = now.ToDateAndTimeInSortableFormatForFileSystem() + "-" + now.Millisecond.ToString().PadLeft(3,'0');
				string sendersEMailAddress = "Unknown";
				string receiversEMailAddress = "Unknown";
				string subject = string.Empty;

				string filePath = args[0];
				string destinationFolderForClonedEmlFiles = null;
				bool shouldDeleteClonedEmlFileAfterProcessing = true;
				bool shouldDeleteClonedEmlFileFolderAfterProcessing = false;
				bool shouldDeleteExtractedEmlContentAfterProcessing = false;
				long maxSizeOfEmlFileThatWillBeProcessedInKBytes = -1;
				long virusIsNeverLargerThanXKBytes = -1;
				List<string> virusFileNameExtensions = null;
				List<string> virusPhrases = null;
				int virusNeverHasMoreThanXFilesPackedInZip = -1;
				List<string> virusFileNameExtensionsInZip = null;
				bool shouldCopyVirusToDestinationFolder = false;
				string destinationFolderForDetectedVirus = null;
				int whichNumberToReturnIfIsVirus = -1;
				int whichNumberToReturnIfIsNotVirus = -1;
				List<string> trustedEMails = null;


				using (log.LogScope("Processing '" + filePath.ToNonNullString("null") + "' ..."))
				{
					using (log.LogScope("Reading and parsing parameters... "))
					{
					
						destinationFolderForClonedEmlFiles = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<string>("destinationFolderForClonedEmlFiles", null, true, null, false, string.Empty, false, null, '=');
						log.AddLine("destinationFolderForClonedEmlFiles=" + destinationFolderForClonedEmlFiles);
						
						shouldDeleteClonedEmlFileAfterProcessing = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<bool>("shouldDeleteClonedEmlFileAfterProcessing", null, true, false, true, false, false, false, '=');
						log.AddLine("shouldDeleteClonedEmlFileAfterProcessing=" + shouldDeleteClonedEmlFileAfterProcessing);

						shouldDeleteExtractedEmlContentAfterProcessing = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<bool>("shouldDeleteExtractedEmlContentAfterProcessing", null, true, false, true, false, false, false, '=');
						log.AddLine("shouldDeleteExtractedEmlContentAfterProcessing=" + shouldDeleteExtractedEmlContentAfterProcessing);
						
						maxSizeOfEmlFileThatWillBeProcessedInKBytes = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<long>("maxSizeOfEmlFileThatWillBeProcessed", null, true, -1, false, long.MaxValue, false, -1, '=');
						log.AddLine("maxSizeOfEmlFileThatWillBeProcessedInKBytes=" + maxSizeOfEmlFileThatWillBeProcessedInKBytes);
						

						virusIsNeverLargerThanXKBytes = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<long>("virusIsNeverLargerThanXKBytes", null, true, -1, false, long.MaxValue, false, -1, '=');
						log.AddLine("virusIsNeverLargerThanXKBytes=" + virusIsNeverLargerThanXKBytes);

						string virusFileNameExtensionsCsv = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<string>("virusFileNameExtensionsCsv", null, true, null, false, string.Empty, false, null, '=');
						log.AddLine("virusFileNameExtensionsCsv=" + virusFileNameExtensionsCsv);
						virusFileNameExtensions = virusFileNameExtensionsCsv.IsNullOrWhiteSpace() ? new List<string>() : virusFileNameExtensionsCsv.ParseCSV();

						string virusPhrasesCsv = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<string>("virusPhrasesCsv", null, true, null, false, string.Empty, false, null, '=');
						log.AddLine("virusPhrasesCsv=" + virusPhrasesCsv);
						virusPhrases = virusPhrasesCsv.IsNullOrWhiteSpace() ? new List<string>() : virusPhrasesCsv.ParseCSV(new []{'|'});

						virusNeverHasMoreThanXFilesPackedInZip = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<int>("virusNeverHasMoreThanXFilesPackedInZip", null, true, -1, true, -1, false, -1, '=');
						log.AddLine("virusNeverHasMoreThanXFilesPackedInZip=" + virusNeverHasMoreThanXFilesPackedInZip);

						string virusFileNameExtensionsInZipCsv = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<string>("virusFileNameExtensionsInZipCsv", null, true, null, false, string.Empty, false, null, '=');
						log.AddLine("virusFileNameExtensionsInZipCsv=" + virusFileNameExtensionsInZipCsv);
						virusFileNameExtensionsInZip = virusFileNameExtensionsInZipCsv.IsNullOrWhiteSpace() ? new List<string>() : virusFileNameExtensionsInZipCsv.ParseCSV();

						shouldCopyVirusToDestinationFolder = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<bool>("shouldCopyVirusToDestinationFolder", null, true, false, true, false, false, false, '=');
						log.AddLine("shouldCopyVirusToDestinationFolder=" + shouldCopyVirusToDestinationFolder);

						destinationFolderForDetectedVirus = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<string>("destinationFolderForDetectedVirus", null, true, null, false, string.Empty, false, null, '=');
						log.AddLine("destinationFolderForDetectedVirus=" + destinationFolderForDetectedVirus);

						whichNumberToReturnIfIsVirus = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<int>("whichNumberToReturnIfIsVirus", null, true, -1, true, -1, false, -1, '=');
						log.AddLine("whichNumberToReturnIfIsVirus=" + whichNumberToReturnIfIsVirus);

						whichNumberToReturnIfIsNotVirus = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<int>("whichNumberToReturnIfIsNotVirus", null, true, -1, true, -1, false, -1, '=');
						log.AddLine("whichNumberToReturnIfIsNotVirus=" + whichNumberToReturnIfIsNotVirus);


						string trustedEMailsCsv = CraftSynth.BuildingBlocks.IO.FileSystem.GetSettingFromIniFile<string>("trustedEMailsCsv", null, true, null, false, string.Empty, false, null, '=');
						log.AddLine("trustedEMailsCsv=" + trustedEMailsCsv);
						trustedEMails = trustedEMailsCsv.IsNullOrWhiteSpace() ? new List<string>() : trustedEMailsCsv.ParseCSV();
					}


					using (log.LogScope("Processing mail '" + filePath.ToNonNullString() + "'..."))
					{
						if (filePath.IsNullOrWhiteSpace())
						{
							throw new Exception("filePath can not be null or empty.");
						}
						if (string.Compare(Path.GetExtension(filePath).Trim('.'), "eml", StringComparison.OrdinalIgnoreCase) != 0 && string.Compare(Path.GetExtension(filePath).Trim('.'), "tmp", StringComparison.OrdinalIgnoreCase) != 0)
						{
							throw new Exception("Only .eml file type is supported however file extension can be .eml or .tmp.");
						}
						if (!File.Exists(filePath))
						{
							throw new Exception("File not found:" + filePath.ToNonNullString());
						}

						#region clone .eml file and set filePath to that new file

						using (log.LogScope("Cloning .eml to destinationFolderForClonedEmlFiles..."))
						{
							//we need to clone hServerMail .tmp file in order to change it extension to .eml -only that extension is accepted by MsgReader.
							if (destinationFolderForClonedEmlFiles.StartsWith(@"\"))
							{
								destinationFolderForClonedEmlFiles = Path.Combine(BuildingBlocks.Common.Misc.ApplicationRootFolderPath, destinationFolderForClonedEmlFiles.TrimStart('\\'));
							}

							shouldDeleteClonedEmlFileFolderAfterProcessing = shouldDeleteClonedEmlFileAfterProcessing && destinationFolderForClonedEmlFiles.Contains("{0}");
							destinationFolderForClonedEmlFiles = destinationFolderForClonedEmlFiles.Replace("{0}", nowUniqueString);
							string destinationFilePath = Path.Combine(destinationFolderForClonedEmlFiles, nowUniqueString + ".eml"); //Path.GetFileName(filePath));
							log.AddLine("destinationFilePath=" + destinationFilePath);
							if (!Directory.Exists(Path.GetDirectoryName(destinationFilePath)))
							{
								using (log.LogScope("Creating directory..."))
								{
									Directory.CreateDirectory(Path.GetDirectoryName(destinationFilePath));
								}
							}

							using (log.LogScope("Performing copy..."))
							{
								File.Copy(filePath, destinationFilePath, true);
								filePath = destinationFilePath;                   //!!!
							}
						}
						#endregion

						try
						{
							log.AddLine("Checking against .eml file size...");
							long? emlFileSize = BuildingBlocks.IO.FileSystem.GetFileSizeInBytes(filePath, false);
							if (emlFileSize == null)
							{
								throw new Exception("Could not determine .eml file size.");
							}
							if (emlFileSize > maxSizeOfEmlFileThatWillBeProcessedInKBytes*1024)
							{
								log.AddLine(".eml too big for processing. assume it seems clean.", false);
								r = whichNumberToReturnIfIsNotVirus;
							}
							else
							{
								using (log.LogScope("Parsing .eml file..."))
								{
									string extractedEmlFolderPath = Path.Combine(Path.GetDirectoryName(filePath), "_extractedEml_" + nowUniqueString);
									log.AddLine("extractedEmlFolderPath=" + extractedEmlFolderPath);
									if (!Directory.Exists(extractedEmlFolderPath))
									{
										using (log.LogScope("Creating extractedEmlFolderPath folder..."))
										{
											Directory.CreateDirectory(extractedEmlFolderPath);
										}
									}

									try
									{
										List<string> emailBodyAndAttachmentsFilePaths = null;
										using (log.LogScope("Extracting .eml file..."))
										{
											try
											{
												var msgReader = new MsgReader.Reader(); //https://www.codeproject.com/Tips/712072/Reading-an-Outlook-MSG-File-in-Csharp
												emailBodyAndAttachmentsFilePaths = msgReader.ExtractToFolder(filePath, extractedEmlFolderPath).ToList();
												if (emailBodyAndAttachmentsFilePaths.Count == 0)
												{
													throw new Exception("Nothing extracted from .eml file.");
												}
											}
											catch (Exception e)
											{
												throw new Exception("Error occured during extraction of .eml file.", e);
											}
										}

										string eMailHeadingAndBody = File.ReadAllText(emailBodyAndAttachmentsFilePaths[0]).ToNonNullString();
										log.AddLine("Checking against virus phrases...");
										if (virusPhrases.Any(p => eMailHeadingAndBody.ToLower().Contains(p.ToLower())))
										{
											log.AddLine("Virus phrase found. virus detected.");
											r = whichNumberToReturnIfIsVirus;
										}
										else
										{
											log.AddLine("Virus phrase not found. needs further checks.");


											bool isPlainText = emailBodyAndAttachmentsFilePaths[0].ToLower().EndsWith(".txt");
											log.AddLine("isPlainText: " + isPlainText);

											using (log.LogScope("Finding sender's email..."))
											{
												if (isPlainText)
												{
													var lines = File.ReadAllLines(emailBodyAndAttachmentsFilePaths[0]);
													sendersEMailAddress = lines[0].GetSubstring("<", ">");
													subject = lines[3].GetSubstringAfter("Subject:").ToNonNullString().Trim();
													receiversEMailAddress = lines[2].GetSubstring("<", ">");
												}
												else
												{
													//find first '"mailto:' phrase or @ sign
													//var text = File.ReadAllText(emailBodyAndAttachmentsFilePaths[0]);
													sendersEMailAddress = eMailHeadingAndBody.GetSubstring("&lt;", "&gt;"); //>Example: From:</td><td>f4cio&nbsp&lt;f4cio@f4cio.com&gt;</td></tr>
													subject = eMailHeadingAndBody.GetSubstring("Subject:</td><td>", "<br/>");
													receiversEMailAddress = eMailHeadingAndBody.GetSubstring("To:</td><td>", "</td>");
												}
												if (sendersEMailAddress.IsNullOrWhiteSpace())
												{
													throw new Exception("Failed to parse sender's email.");
												}
												log.AddLine("   FROM: " + sendersEMailAddress.ToNonNullString("null"));
												log.AddLine("     TO: " + receiversEMailAddress.ToNonNullString("null"));
												log.AddLine("SUBJECT: " + subject.ToNonNullString("null"));
											}

											log.AddLine("Checking against trusted emails...");
											if (trustedEMails.Any(e => string.Compare(e, sendersEMailAddress, StringComparison.OrdinalIgnoreCase) == 0))
											{
												log.AddLine("EMail is from trusted sender. seems clean.");
												r = whichNumberToReturnIfIsNotVirus;
											}
											else
											{
												log.AddLine("EMail is not from trusted sender. Needs further checks.");

												if (emailBodyAndAttachmentsFilePaths.Count == 1)
												{
													log.AddLine("There are no attachments. Nothing more to check. seems clean.");
													r = whichNumberToReturnIfIsNotVirus;
												}
												else
												{
													if (emailBodyAndAttachmentsFilePaths.Count > 2)
													{
														log.AddLine("There is more than one attachment. Assuming it is not virus. seems clean.");
														r = whichNumberToReturnIfIsNotVirus;
													}
													else
													{
														using (log.LogScope("Checking attachment..."))
														{
															string attachmentFilePath = emailBodyAndAttachmentsFilePaths[1];
															if (!File.Exists(attachmentFilePath))
															{
																throw new Exception("File not found:" + attachmentFilePath.ToNonNullString());
															}

															log.AddLine("Checking against file size...");
															long? fileSize = BuildingBlocks.IO.FileSystem.GetFileSizeInBytes(attachmentFilePath, false);
															if (fileSize == null)
															{
																throw new Exception("Could not determine file size.");
															}
															if (fileSize > virusIsNeverLargerThanXKBytes*1024)
															{
																log.AddLine("seems clean.", false);
																r = whichNumberToReturnIfIsNotVirus;
															}
															else
															{
																log.AddLine("Needs further checks.", false);
																log.AddLine("Checking against extension...");
																var ext = Path.GetExtension(attachmentFilePath).Trim('.');
																if (virusFileNameExtensions.Exists(e => string.Compare(e, ext, StringComparison.OrdinalIgnoreCase) == 0))
																{
																	log.AddLine("virus detected.");
																	r = whichNumberToReturnIfIsVirus;
																}
																else
																{
																	log.AddLine("Needs further checks.", false);
																	log.AddLine("Checking wether is zip...");
																	if (string.Compare(ext, "zip", StringComparison.OrdinalIgnoreCase) != 0)
																	{
																		log.AddLine("not zip. seems clean.", false);
																		r = whichNumberToReturnIfIsNotVirus;
																	}
																	else
																	{
																		log.AddLine("it is zip. Needs further checks.", false);
																		using (ZipFile zip = ZipFile.Read(attachmentFilePath))
																		{
																			log.AddLine("Zipfile:" + zip.Name);
																			log.AddLine("Comment:" + zip.Comment.ToNonNullString("null"));

																			if (zip.Count == 0)
																			{
																				log.AddLine("No files in zip. seems clean.");
																				r = whichNumberToReturnIfIsNotVirus;
																			}
																			else if (zip.Count > virusNeverHasMoreThanXFilesPackedInZip)
																			{
																				log.AddLine("Too many files in zip. seems clean.");
																				r = whichNumberToReturnIfIsNotVirus;
																			}
																			else
																			{
																				foreach (ZipEntry e in zip)
																				{
																					log.AddLine(string.Format("FileName={0}, LastModified={1}, Uncompressed={2} bytes, Compression={3:0.00}%, Compressed={4} bytes, Encrypted={5}",
																						e.FileName,
																						e.LastModified.ToString("yyyy-MM-dd HH:mm:ss"),
																						e.UncompressedSize,
																						e.CompressionRatio,
																						e.CompressedSize,
																						(e.UsesEncryption) ? "Y" : "N"));

																					if (virusFileNameExtensionsInZip.Exists(e1 => string.Compare(e1, Path.GetExtension(e.FileName).Trim('.'), StringComparison.OrdinalIgnoreCase) == 0))
																					{
																						log.AddLine("virus detected.");
																						r = whichNumberToReturnIfIsVirus;
																					}
																				}
																				if (r == null)
																				{
																					log.AddLine("seems clean.");
																					r = whichNumberToReturnIfIsNotVirus;
																				}
																			}
																		}

																	}
																}
															}
														}
													}
												}
											}
										}
									}
									finally
									{
										if (shouldDeleteExtractedEmlContentAfterProcessing)
										{
											try
											{
												Directory.Delete(extractedEmlFolderPath, true);
											}
											catch (Exception e)
											{
												log.AddLine("Couldn't delete extractedEmlFolderPath folder. Error:" + e.Message);
											}
										}
									}
								}
							}

							if (r == whichNumberToReturnIfIsVirus && shouldCopyVirusToDestinationFolder)
							{
								using (log.LogScope("Copying .eml to destinationFolderForDetectedVirus..."))
								{
									if (destinationFolderForDetectedVirus.StartsWith(@"\"))
									{
										destinationFolderForDetectedVirus = Path.Combine(BuildingBlocks.Common.Misc.ApplicationRootFolderPath, destinationFolderForDetectedVirus.TrimStart('\\'));
									}
									destinationFolderForDetectedVirus = destinationFolderForDetectedVirus.Replace("{0}", nowUniqueString);
									string destinationFilePath = Path.Combine(destinationFolderForDetectedVirus, nowUniqueString+" From "+sendersEMailAddress.ToNonNullString("null")+" to "+receiversEMailAddress.ToNonNullString("null")+" "+subject.ReplaceNonAlphaNumericCharacters("_").FirstXChars(100, "... ")+".eml");
									log.AddLine("destinationFilePath=" + destinationFilePath);
									if (!Directory.Exists(Path.GetDirectoryName(destinationFilePath)))
									{
										using (log.LogScope("Creating directory..."))
										{
											Directory.CreateDirectory(Path.GetDirectoryName(destinationFilePath));
										}
									}

									using (log.LogScope("Performing copy..."))
									{
										File.Copy(filePath, destinationFilePath, true);
									}

									try
									{
										File.WriteAllText(Path.ChangeExtension(destinationFilePath,".txt"), log.ToString());
									}
									catch (Exception)
									{
									}
								}
							}
						}
						finally
						{
							try
							{
								using (log.LogScope("Cleaning up cloned file/its folder..."))
								{
									if (shouldDeleteClonedEmlFileFolderAfterProcessing)
									{
										Directory.Delete(Path.GetDirectoryName(filePath), true);
									}
									else if (shouldDeleteClonedEmlFileAfterProcessing)
									{
										File.Delete(filePath);
									}
									else
									{
										try
										{
											File.WriteAllText(Path.Combine(Path.GetDirectoryName(filePath),nowUniqueString+".txt"), log.ToString());
										}
										catch (Exception)
										{
										}
									}
								}
							}
							catch (Exception e)
							{
								log.AddLine("Couldn't delete cloned file/its folder. Error:" + e.Message);
							}
						}
					}
				}
			}
			catch (Exception e)
			{
				log.AddLine("Error:"+e.Message);
				e = BuildingBlocks.Common.Misc.GetDeepestException(e);
				log.AddLine("Deepest exception:"+e.Message);
				log.AddLine("StackTrace:"+e.StackTrace);
				r = whichNumberToReturnIfErrorOccured;
			}

			log.AddLine("Exit code: "+r);
			return r.Value;
		}

		private static void CustomTraceLogAddLinePostProcessingEvent(BuildingBlocks.Logging.CustomTraceLog log, string line, bool inNewLine, int level, string lineVersionSuitableForLineEnding, string lineVersionSuitableForNewLine)
		{
			string logFilePath = BuildingBlocks.Common.Misc.ApplicationPhysicalExeFilePathWithoutExtension + ".log";
			BuildingBlocks.IO.FileSystem.AppendFile(logFilePath, inNewLine?"\r\n"+lineVersionSuitableForNewLine:lineVersionSuitableForLineEnding, FileSystem.ConcurrencyProtectionMechanism.Lock, null);
			Console.Write((inNewLine ? "\r\n" + line : line));
		}
	}
}
