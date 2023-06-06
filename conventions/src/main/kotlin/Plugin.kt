import org.gradle.api.*
class AspConventions: Plugin<Project> {
    override fun apply(target: Project) {
       target.rootProject.plugins.apply("io.github.gradle-nexus.publish-plugin")
    }
}