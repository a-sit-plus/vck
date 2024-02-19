rootProject.name = "vclib-conventions"

//we don't want to pollute the classpath with a shadowed conventions plugin
System.setProperty("at.asitplus.gradle", "legacy")
includeBuild("gradle-conventions-plugin")