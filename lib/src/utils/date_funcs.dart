// Helper functions for manipulating UTC timestamps.

/// Parses a timestamp in the CCYY-MM-DDThh:mm:ssZ form into a UTC [DateTime].
DateTime parseDateClass(String value) {
  final trimmed = value.trim();
  final datePieces = trimmed.split('-');
  if (datePieces.length != 3) {
    throw FormatException('Invalid date format, expected YYYY-MM-DD', value);
  }

  final year = int.parse(datePieces[0]);
  final month = int.parse(datePieces[1]);

  final dayToken = datePieces[2];
  if (dayToken.length < 2) {
    throw FormatException('Invalid day component', value);
  }

  final day = int.parse(dayToken.substring(0, 2));
  final tail = dayToken.substring(2);
  if (!tail.startsWith('T')) {
    throw FormatException('Missing time separator (T)', value);
  }

  final timePieces = tail.substring(1).split(':');
  if (timePieces.length != 3) {
    throw FormatException('Invalid time component', value);
  }

  final hour = int.parse(timePieces[0]);
  final minute = int.parse(timePieces[1]);
  final secondToken = timePieces[2];
  if (secondToken.length < 2) {
    throw FormatException('Invalid seconds component', value);
  }

  final second = int.parse(secondToken.substring(0, 2));
  return createDateClass(year, month, day, hour, minute, second);
}

/// Creates a UTC [DateTime] instance.
DateTime createDateClass(
  int year,
  int month,
  int day,
  int hour,
  int minute,
  int second,
) {
  return DateTime.utc(year, month, day, hour, minute, second);
}

/// Renders the timestamp as CCYY-MM-DDThh:mm:ssZ.
String printDateClass(DateTime dateTime) {
  final utc = dateTime.toUtc();
  final twoDigits = (int value) => value.toString().padLeft(2, '0');
  final year = utc.year.toString().padLeft(4, '0');
  final month = twoDigits(utc.month);
  final day = twoDigits(utc.day);
  final hour = twoDigits(utc.hour);
  final minute = twoDigits(utc.minute);
  final second = twoDigits(utc.second);
  return '$year-$month-${day}T$hour:$minute:${second}Z';
}

/// Returns the current UTC time.
DateTime getNow() => DateTime.now().toUtc();

/// Returns a UTC timestamp that is [hours] hours ahead of now.
DateTime getHoursFromNow(int hours) {
  return getNow().add(Duration(hours: hours));
}

/// Returns a UTC timestamp that is [minutes] minutes ahead of now.
DateTime getMinutesFromNow(int minutes) {
  return getNow().add(Duration(minutes: minutes));
}

/// Indicates whether [dateTime] is already in the past (UTC).
bool isDateClassExpired(DateTime dateTime) {
  return dateTime.isBefore(getNow());
}

/// Indicates whether [left] occurs before [right].
bool isDateClassBefore(DateTime left, DateTime right) {
  return left.isBefore(right);
}
